package accounts

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"unicode/utf8"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// SetTemporaryPassword sets the account's password to pw, marked temporary,
// so its next sign-in must choose a new one: PUT /users/{id}/reset-password
// (geekdojo/geekdojo-brain#992; #321's accounts.repair_reset can reuse it).
// It returns the Admin API's status, 0 when none was received. Our Keycloak
// build answers a policy refusal here with 500, since features-disabled=admin
// leaves no admin theme to build the 400's message from (capability rows
// T170 and T202; finding F-1145-41, geekdojo/geekdojo-brain#1145); the caller
// tells it apart from a fault.
func (u *Users) SetTemporaryPassword(ctx context.Context, sub string, pw secret.Value) (int, error) {
	if sub == "" || pw.Len() == 0 {
		return 0, errors.New("accounts: no account id or no password")
	}
	resp, err := u.d.Admin.Admin(ctx, http.MethodPut, u.userPath(sub)+"/reset-password", temporaryPassword{pw: pw}, nil)
	if err != nil {
		var ie *idclient.Error
		status := 0
		if errors.As(err, &ie) {
			status = ie.Status
		}
		return status, fmt.Errorf("accounts: set the temporary password: %w", err)
	}
	return resp.Status, nil
}

// temporaryPassword is the credential representation reset-password takes.
// It marshals itself so the password's bytes go only into the request body,
// which the identity client zeroes once the call returns.
type temporaryPassword struct{ pw secret.Value }

// MarshalJSON writes {"type":"password","temporary":true,"value":<pw>},
// the value JSON-escaped byte by byte.
func (t temporaryPassword) MarshalJSON() ([]byte, error) {
	const head, tail = `{"type":"password","temporary":true,"value":"`, `"}`
	b := t.pw.Reveal()
	out := make([]byte, 0, len(head)+6*len(b)+len(tail))
	out = append(out, head...)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size <= 1 {
			clear(out)
			return nil, errors.New("accounts: the password is not valid UTF-8")
		}
		switch {
		case r == '"' || r == '\\':
			out = append(out, '\\', byte(r))
		case r < 0x20 || r == 0x2028 || r == 0x2029:
			out = append(out, `\u`...)
			out = append(out, fmt.Sprintf("%04x", r)...)
		default:
			out = append(out, b[:size]...)
		}
		b = b[size:]
	}
	return append(out, tail...), nil
}

// statusText is a status for a log record: "none" when no answer came.
func statusText(status int) string {
	if status == 0 {
		return "none"
	}
	return strconv.Itoa(status)
}
