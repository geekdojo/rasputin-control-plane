package apprelay

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

var keyOps = []string{proto.AppKeyCreate, proto.AppKeyEncrypt, proto.AppKeyDecrypt, proto.AppKeyDestroy}

func keyCall(t *testing.T, op, name string) Call {
	t.Helper()
	ref, err := secrets.AppKey(appA, name)
	if err != nil {
		t.Fatal(err)
	}
	return Call{Node: nodeN, AppID: appA, Op: op, Ref: ref, Name: name, Value: secret.New([]byte("aGk="))}
}

// TC-1084-12: the key index order. Create checks for and records the row
// before the store create; destroy forgets the row after a successful store
// destroy, and a failed destroy leaves it. Encrypt and decrypt check the row
// and touch no other index. F-1084-22: a create the store refused forgets the
// row it added; a row that was there before, or a store that was unreachable
// (it may have created the key), keeps the row.
func TestService_KeyIndexOrder(t *testing.T) {
	k := "transit:app-" + appA + "-wrap"
	storeDown := errors.New("store down")
	refused := &secretstore.Error{Op: "login", Mount: "auth/cert", Path: "login", Status: 400, Kind: secretstore.ErrProtocol}
	unreachable := &secretstore.Error{Op: "transit_create", Kind: secretstore.ErrUnreachable}
	created := []string{"has key wrap", "record key wrap", "create " + k}
	for _, tc := range []struct {
		name    string
		s       *spy
		op      string
		want    []string
		wantErr error
	}{
		{"create", &spy{app: appOn(appA, nodeN), granted: true, noKey: true}, proto.AppKeyCreate, created, nil},
		{"a refused create forgets the row it added", &spy{app: appOn(appA, nodeN), granted: true, noKey: true, store: refused}, proto.AppKeyCreate, append(slices.Clone(created), "forget key wrap"), secretstore.ErrProtocol},
		{"a refused create keeps a row that was there", &spy{app: appOn(appA, nodeN), granted: true, store: refused}, proto.AppKeyCreate, created, secretstore.ErrProtocol},
		{"an unreachable store keeps the row", &spy{app: appOn(appA, nodeN), granted: true, noKey: true, store: unreachable}, proto.AppKeyCreate, created, secretstore.ErrUnreachable},
		{"a failed create of a row that was there leaves it", &spy{app: appOn(appA, nodeN), granted: true, store: storeDown}, proto.AppKeyCreate, created, storeDown},
		{"an index failure stops the create", &spy{app: appOn(appA, nodeN), granted: true, index: storeDown}, proto.AppKeyCreate, []string{"has key wrap"}, storeDown},
		{"destroy", &spy{app: appOn(appA, nodeN), granted: true}, proto.AppKeyDestroy, []string{"destroy " + k, "forget key wrap"}, nil},
		{"failed destroy leaves the row", &spy{app: appOn(appA, nodeN), granted: true, store: storeDown}, proto.AppKeyDestroy, []string{"destroy " + k}, storeDown},
		{"encrypt checks the row", &spy{app: appOn(appA, nodeN), granted: true, value: "vault:v1:x"}, proto.AppKeyEncrypt, []string{"has key wrap", "encrypt " + k}, nil},
		{"decrypt checks the row", &spy{app: appOn(appA, nodeN), granted: true, value: "aGk="}, proto.AppKeyDecrypt, []string{"has key wrap", "decrypt " + k}, nil},
		{"an index failure stops the encrypt", &spy{app: appOn(appA, nodeN), granted: true, index: storeDown}, proto.AppKeyEncrypt, []string{"has key wrap"}, storeDown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := newSpyService(t, tc.s).Do(t.Context(), keyCall(t, tc.op, "wrap"))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Do = %v, want %v", err, tc.wantErr)
			}
			if got := tc.s.seen(); !slices.Equal(got, tc.want) {
				t.Errorf("calls = %v, want %v", got, tc.want)
			}
			if err == nil && (tc.op == proto.AppKeyEncrypt || tc.op == proto.AppKeyDecrypt) && string(v.Reveal()) != tc.s.value {
				t.Errorf("value %q, want %q", v.Reveal(), tc.s.value)
			}
			v.Destroy()
		})
	}
}

// TC-1084-13: an encrypt or decrypt under a key the app's index does not
// record answers not_found with its own sentence, with no store call and no
// re-login, logged once at WARN as apprelay.refused, never at ERROR.
func TestService_MissingKeyIsNotFound(t *testing.T) {
	for _, op := range []string{proto.AppKeyEncrypt, proto.AppKeyDecrypt} {
		t.Run(op, func(t *testing.T) {
			s := &spy{app: appOn(appA, nodeN), granted: true, noKey: true}
			h, rec := newTestHandler(t, newSpyService(t, s))
			pub := &capture{}
			value := "aGk="
			if op == proto.AppKeyDecrypt {
				value = "vault:v1:aGVsbG8="
			}
			h.Handle(t.Context(), pub, proto.AppSecretCallSubject(nodeN), proto.AppSecretReplyPrefix(nodeN)+"tok", body(op, appA, "ghost", value))
			r := pub.reply(t)
			if r.Code != proto.AppSecretNotFound || r.Message != msgNoKey {
				t.Errorf("reply %+v, want not_found %q", r, msgNoKey)
			}
			if got := s.seen(); !slices.Equal(got, []string{"has key ghost"}) {
				t.Errorf("calls = %v, want only the index check", got)
			}
			if n := len(rec.AtLevel(slog.LevelError)); n != 0 {
				t.Errorf("%d ERROR records", n)
			}
			warns := rec.AtLevel(slog.LevelWarn)
			if len(warns) != 1 {
				t.Fatalf("%d WARN records, want 1", len(warns))
			}
			if ev, _ := logkittest.Attr(warns[0], "event"); ev != "apprelay.refused" {
				t.Errorf("event %q", ev)
			}
		})
	}
}

// TC-1084-14: a key op from an app that does not exist, is not granted, or
// is on another node answers forbidden, with no index write and no store
// call.
func TestService_KeyGateRunsFirst(t *testing.T) {
	for name, s := range map[string]func() *spy{
		"no app":      func() *spy { return &spy{granted: true} },
		"not granted": func() *spy { return &spy{app: appOn(appA, nodeN)} },
		"wrong node":  func() *spy { return &spy{app: appOn(appA, nodeM), granted: true} },
	} {
		for _, op := range keyOps {
			t.Run(name+" "+op, func(t *testing.T) {
				sp := s()
				h, _ := newTestHandler(t, newSpyService(t, sp))
				pub := &capture{}
				value := ""
				switch op {
				case proto.AppKeyEncrypt:
					value = "aGk="
				case proto.AppKeyDecrypt:
					value = "vault:v1:aGk="
				}
				h.Handle(t.Context(), pub, proto.AppSecretCallSubject(nodeN), proto.AppSecretReplyPrefix(nodeN)+"tok", body(op, appA, "wrap", value))
				if r := pub.reply(t); r.Code != proto.AppSecretForbidden {
					t.Errorf("reply %+v, want forbidden", r)
				}
				if got := sp.seen(); len(got) != 0 {
					t.Errorf("calls = %v, want none", got)
				}
			})
		}
	}
}

// TC-1084-15: parseCall for key ops: a bad key name, encrypt plaintext that is
// not base64, and decrypt input not of the form vault:v<1-10 digits>:<base64>
// are invalid; a well-formed vault:v1: input is accepted; an unknown op is
// invalid; the reference's app is the stamped AppID.
func TestParseCall_Keys(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte("hello"))
	for _, tc := range []struct {
		name, op, key, value string
		ok                   bool
	}{
		{"create", proto.AppKeyCreate, "wrap", "", true},
		{"destroy", proto.AppKeyDestroy, "wrap", "", true},
		{"encrypt base64", proto.AppKeyEncrypt, "wrap", good, true},
		{"encrypt empty", proto.AppKeyEncrypt, "wrap", "", true},
		{"decrypt vault:v1", proto.AppKeyDecrypt, "wrap", "vault:v1:" + good, true},
		{"decrypt ten digits", proto.AppKeyDecrypt, "wrap", "vault:v1234567890:" + good, true},
		{"bad key name", proto.AppKeyCreate, "Wrap", "", false},
		{"key name with a slash", proto.AppKeyCreate, "a/b", "", false},
		{"encrypt not base64", proto.AppKeyEncrypt, "wrap", "not base64!", false},
		{"encrypt unpadded", proto.AppKeyEncrypt, "wrap", strings.TrimRight(good, "="), false},
		{"decrypt no version", proto.AppKeyDecrypt, "wrap", "vault:v:" + good, false},
		{"decrypt eleven digits", proto.AppKeyDecrypt, "wrap", "vault:v12345678901:" + good, false},
		{"decrypt plain base64", proto.AppKeyDecrypt, "wrap", good, false},
		{"decrypt empty", proto.AppKeyDecrypt, "wrap", "", false},
		{"decrypt bad tail", proto.AppKeyDecrypt, "wrap", "vault:v1:@@", false},
		{"unknown key op", "key.rotate", "wrap", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, why := parseCall(nodeN, body(tc.op, appA, tc.key, tc.value))
			defer c.Value.Destroy()
			if (why == "") != tc.ok {
				t.Fatalf("parseCall = %q, want ok=%t", why, tc.ok)
			}
			if !tc.ok {
				return
			}
			want, _ := secrets.AppKey(appA, tc.key)
			if c.Ref != want || c.AppID != appA || c.Node != nodeN {
				t.Errorf("call %+v, want the stamped app's key", c)
			}
			if got := string(c.Value.Reveal()); got != tc.value {
				t.Errorf("value %q, want %q", got, tc.value)
			}
		})
	}
}

// TC-1084-16 (api side): the largest plaintext the bound accepts parses, its
// largest ciphertext (10-digit version) parses for decrypt, and one byte more
// plaintext is invalid.
func TestParseCall_KeySizeBound(t *testing.T) {
	maxPT := base64.StdEncoding.EncodeToString(make([]byte, proto.AppKeyMaxPlaintextBytes))
	maxCT := "vault:v" + strings.Repeat("9", 10) + ":" + base64.StdEncoding.EncodeToString(make([]byte, 12+proto.AppKeyMaxPlaintextBytes+16))
	over := base64.StdEncoding.EncodeToString(make([]byte, proto.AppKeyMaxPlaintextBytes+1))
	for _, tc := range []struct {
		name, op, value string
		ok              bool
	}{
		{"the largest plaintext", proto.AppKeyEncrypt, maxPT, true},
		{"its largest ciphertext", proto.AppKeyDecrypt, maxCT, true},
		{"one byte over", proto.AppKeyEncrypt, over, false},
		{"a ciphertext over the value bound", proto.AppKeyDecrypt, "vault:v1:" + strings.Repeat("A", proto.AppRelayMaxValueBytes), false},
	} {
		c, why := parseCall(nodeN, body(tc.op, appA, "wrap", tc.value))
		c.Value.Destroy()
		if (why == "") != tc.ok {
			t.Errorf("%s: parseCall = %q, want ok=%t", tc.name, why, tc.ok)
		}
	}
}

// TC-1084-17: each error maps to its code for every key op; refusals are one
// WARN apprelay.refused with the call's fields and a reason, store failures
// one ERROR apprelay.store_failed with err; no record and no reply message
// carries the plaintext, its base64 or the ciphertext.
func TestHandler_KeyErrorCodes(t *testing.T) {
	const plaintext = "sentinel-plaintext-1084-17"
	b64 := base64.StdEncoding.EncodeToString([]byte(plaintext))
	const ciphertext = "vault:v1:c2VudGluZWwtY2lwaGVydGV4dC0xMDg0LTE3"
	storeText := errors.New("bao: 500 internal path rasputin-app-keys/encrypt/x")
	for _, tc := range []struct {
		name  string
		err   error
		code  string
		level slog.Level
		event string
	}{
		{"forbidden", fmt.Errorf("x: %w", secrets.ErrForbidden), proto.AppSecretForbidden, slog.LevelWarn, "apprelay.refused"},
		{"no app", fmt.Errorf("x: %w", ErrNoApp), proto.AppSecretForbidden, slog.LevelWarn, "apprelay.refused"},
		{"not granted", fmt.Errorf("x: %w", ErrNotGranted), proto.AppSecretForbidden, slog.LevelWarn, "apprelay.refused"},
		{"wrong node", fmt.Errorf("x: %w", ErrWrongNode), proto.AppSecretForbidden, slog.LevelWarn, "apprelay.refused"},
		{"no key", fmt.Errorf("x: %w", ErrNoKey), proto.AppSecretNotFound, slog.LevelWarn, "apprelay.refused"},
		{"absent in the store", fmt.Errorf("x: %w", secretstore.ErrNotFound), proto.AppSecretNotFound, slog.LevelWarn, "apprelay.refused"},
		{"bad ciphertext", fmt.Errorf("x: %w", secretstore.ErrInvalidCiphertext), proto.AppSecretInvalid, slog.LevelWarn, "apprelay.refused"},
		{"store denied", fmt.Errorf("%w: %w", secretstore.ErrDenied, storeText), proto.AppSecretUnavailable, slog.LevelError, "apprelay.store_failed"},
		{"store unreachable", fmt.Errorf("%w: %w", secretstore.ErrUnreachable, storeText), proto.AppSecretUnavailable, slog.LevelError, "apprelay.store_failed"},
		// TC-1084-11: the switched-off store answers unavailable.
		{"store disabled", fmt.Errorf("x: %w", secretstore.ErrDisabled), proto.AppSecretUnavailable, slog.LevelError, "apprelay.store_failed"},
	} {
		for _, op := range keyOps {
			t.Run(tc.name+" "+op, func(t *testing.T) {
				h, rec := newTestHandler(t, &stubCaller{err: tc.err})
				pub := &capture{}
				value := ""
				switch op {
				case proto.AppKeyEncrypt:
					value = b64
				case proto.AppKeyDecrypt:
					value = ciphertext
				}
				h.Handle(t.Context(), pub, proto.AppSecretCallSubject(nodeN), proto.AppSecretReplyPrefix(nodeN)+"tok", body(op, appA, "wrap", value))
				r := pub.reply(t)
				if r.Code != tc.code || r.CorrelationID == "" || !strings.HasSuffix(r.Message, ".") || r.Value != "" {
					t.Errorf("reply %+v, want code %s with a sentence, a correlation id and no value", r, tc.code)
				}
				for _, v := range []string{plaintext, b64, ciphertext, "bao"} {
					if strings.Contains(r.Message, v) {
						t.Errorf("the reply message carries %q", v)
					}
					if v != "bao" && strings.Contains(rec.Text(), v) {
						t.Errorf("a log record carries %q", v)
					}
				}
				recs := rec.AtLevel(tc.level)
				if len(recs) != 1 || len(rec.Records()) != 1 {
					t.Fatalf("%d records at %v of %d, want exactly 1", len(recs), tc.level, len(rec.Records()))
				}
				for k, want := range map[string]string{"component": "apprelay", "event": tc.event, "node": nodeN, "app_id": appA, "op": op, "name": "wrap", "correlation_id": r.CorrelationID} {
					if got, _ := logkittest.Attr(recs[0], k); got != want {
						t.Errorf("%s = %q, want %q", k, got, want)
					}
				}
				field := "reason"
				if tc.event == "apprelay.store_failed" {
					field = "err"
				}
				if got, ok := logkittest.Attr(recs[0], field); !ok || got == "" {
					t.Errorf("the record has no %s", field)
				}
			})
		}
	}
	t.Run("ok encrypt and decrypt carry the value; create and destroy none", func(t *testing.T) {
		for _, op := range keyOps {
			h, rec := newTestHandler(t, &stubCaller{value: "out"})
			pub := &capture{}
			value := ""
			switch op {
			case proto.AppKeyEncrypt:
				value = b64
			case proto.AppKeyDecrypt:
				value = ciphertext
			}
			h.Handle(t.Context(), pub, proto.AppSecretCallSubject(nodeN), proto.AppSecretReplyPrefix(nodeN)+"tok", body(op, appA, "wrap", value))
			r := pub.reply(t)
			wantValue := ""
			if op == proto.AppKeyEncrypt || op == proto.AppKeyDecrypt {
				wantValue = "out"
			}
			if r.Code != proto.AppSecretOK || r.Value != wantValue || r.Message != okMessage[op] {
				t.Errorf("%s: reply %+v", op, r)
			}
			if n := len(rec.Records()); n != 0 {
				t.Errorf("%s: %d records for a success", op, n)
			}
		}
	})
}

// F-1084-22: when forgetting the row of a refused create fails, the call
// returns both the store's refusal and the index failure, so the reply still
// maps from the store's kind and the log names the row left behind.
func TestService_RefusedCreateForgetFails(t *testing.T) {
	refused := &secretstore.Error{Op: "transit_create", Status: 400, Kind: secretstore.ErrProtocol}
	dbDown := errors.New("db down")
	s := &spy{app: appOn(appA, nodeN), granted: true, noKey: true, store: refused, forgetKey: dbDown}
	_, err := newSpyService(t, s).Do(t.Context(), keyCall(t, proto.AppKeyCreate, "wrap"))
	if !errors.Is(err, secretstore.ErrProtocol) || !errors.Is(err, dbDown) {
		t.Fatalf("Do = %v; want the refusal and the index failure", err)
	}
	if !strings.Contains(err.Error(), "forget the row of key wrap") {
		t.Errorf("err = %q; want it to name the row left behind", err)
	}
}
