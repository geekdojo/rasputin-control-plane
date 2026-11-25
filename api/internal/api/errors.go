package api

import (
	"context"
	"log/slog"
	"net/http"
)

// Typed error codes a client can branch on. They follow Human System's error
// codes (api/internal/http/errors.go), the interim reference ARCH-COMMON names
// until the Geekdojo common library (geekdojo/geekdojo-brain#668) exists.
const (
	// codeBusUnavailable: the node bus has no usable key or certificate, so
	// there is no pin to serve and no seed to mint.
	codeBusUnavailable = "bus_unavailable"
	// codeNodeAdmissionUnconfigured: the node listener has no admission gate,
	// so it admits nobody.
	codeNodeAdmissionUnconfigured = "node_admission_unconfigured"
	// codeNodeKeyRequired: the request was not made with a registered node
	// key.
	codeNodeKeyRequired = "node_key_required"
	// codeNodeNotAdmitted: the key's node is no longer a member.
	codeNodeNotAdmitted = "node_not_admitted"
	// codeNodeKeyPurpose: the node presented a key this route is not for.
	codeNodeKeyPurpose = "node_key_wrong_purpose"
	// codeBackupTransferUnconfigured: the node listener admitted the node,
	// but this api has no backup ingest or restore egress wired behind it.
	codeBackupTransferUnconfigured = "backup_transfer_unconfigured"
	// codeCredentialUnreadable: a stored credential the request needs could
	// not be read, so the request was refused rather than sent without it.
	codeCredentialUnreadable = "credential_unreadable"
	// codeFirewallStateUnavailable: the firewall's desired or recorded state
	// could not be read, so whether it is pending or drifted is unknown.
	codeFirewallStateUnavailable = "firewall_state_unavailable"
	// codeRestoreSealBusy: a restore was refused because a seal-key rotation
	// holds the backup capture lock, or the seal files are not settled
	// (geekdojo/geekdojo-brain#765).
	codeRestoreSealBusy = "restore_seal_busy"
	// codeRestoreVersionMismatch: a restore was refused because the backup
	// was not taken on this control-plane version, records no version, or
	// this build carries no version stamp (geekdojo/geekdojo-brain#872).
	codeRestoreVersionMismatch = "restore_version_mismatch"
	// codeNodeSecretsUnavailable: a node removal was refused, with nothing
	// removed, because the secret store cannot take the deletes of its apps'
	// secrets (geekdojo/geekdojo-brain#783).
	codeNodeSecretsUnavailable = "node_secrets_unavailable"
	// codeNodeSecretsUnreadable: a node removal was refused, with nothing
	// removed, because its apps' recorded secrets could not be read.
	codeNodeSecretsUnreadable = "node_secrets_unreadable"
	// codeNodeSecretsLeft: the node was removed, but some of its apps'
	// secrets are still in the secret store.
	codeNodeSecretsLeft = "node_secrets_left"
	// codeBMCCSRInvalid: POST /api/bmc/csr carried no single parseable PEM
	// certificate request (geekdojo/geekdojo-brain#1065).
	codeBMCCSRInvalid = "bmc_csr_invalid"
	// codeBMCCSRRefused: the certificate request parsed, but the BMC signing
	// policy refused it, or no operator was signed in.
	codeBMCCSRRefused = "bmc_csr_refused"
	// codeBMCCSRSignFailed: the request passed the policy, but the
	// controlplane CA could not sign it.
	codeBMCCSRSignFailed = "bmc_csr_sign_failed"
	// codeMemoryFloorMissing: an update pull was refused, with nothing
	// staged, because the release carries the sign-in service but its signed
	// manifest states no control-plane memory floor
	// (geekdojo/geekdojo-brain#1011).
	codeMemoryFloorMissing = "memory_floor_missing"
	// codeMemoryFloorInvalid: an update pull was refused, with nothing
	// staged, because the release states a memory floor that is not a
	// positive number.
	codeMemoryFloorInvalid = "memory_floor_invalid"
	// codeJobSystemOnly: POST /api/jobs named a kind only the system starts,
	// so no job was created (geekdojo/geekdojo-brain#978).
	codeJobSystemOnly = "job_system_only"
	// codeJobCheckFailed: a job's submission could not be decided, because a
	// read the kind table needed failed, so no job was created
	// (geekdojo/geekdojo-brain#1001). The kind table's own refusals answer
	// "job_" + authz.KindRefusal.Code.
	codeJobCheckFailed = "job_check_failed"
	// codeWebPortInvalid: a custom app's "webPort" is not a whole number from
	// 1 to 65535 (geekdojo/geekdojo-brain#1089).
	codeWebPortInvalid = "web_port_invalid"
	// codeWebPortWithoutCompose: PUT /api/apps/{id}/compose carried "webPort"
	// without "composeYaml", the only variant a web port goes beside.
	codeWebPortWithoutCompose = "web_port_without_compose"
	// codeWebPortNotLoopback: a custom app's compose does not publish its web
	// port on 127.0.0.1 only, the tile's loopback rule
	// (geekdojo/geekdojo-brain#1091).
	codeWebPortNotLoopback = "web_port_not_loopback"
	// codeWebPortComposeUnreadable: a custom app has a web port in effect and
	// its compose is not YAML or not a compose's shape, so the publish
	// cannot be checked.
	codeWebPortComposeUnreadable = "web_port_compose_unreadable"
	// codeAppNameReserved: an app name is a label the sign-in doors keep for
	// themselves (proto.IsReservedLabel), so no app was created
	// (geekdojo/geekdojo-brain#983).
	codeAppNameReserved = "app_name_reserved"
	// codeMisdirectedRequest: on :443, the TLS server name and the Host
	// header name different sites (the console, the home sign-in door, the
	// app sign-in door), so the request was refused with 421
	// (geekdojo/geekdojo-brain#986).
	codeMisdirectedRequest = "misdirected_request"
	// codeSigninUnavailable: a sign-in door's site was reached but its door
	// is not being served, so the not-ready page answered 503.
	codeSigninUnavailable = "signin_unavailable"
	// codeRouteNotPermitted: the signed-in person lacks what the route's
	// class needs (geekdojo/geekdojo-brain#1002), so the router refused the
	// request before its handler ran. A Job route's refusal answers the kind
	// table's "job_" code instead.
	codeRouteNotPermitted = "route_not_permitted"
	// The break-glass repair session's codes (geekdojo/geekdojo-brain#321).
	// codeRepairOrigin: a repair code or a repair session was used at an
	// origin other than the console's or the control plane's LAN address, or
	// with an Origin header that differs from the request's own.
	codeRepairOrigin = "repair_origin"
	// codeRepairSourceRefused: the device sent five wrong repair codes, so
	// it is refused until a new code is made.
	codeRepairSourceRefused = "repair_source_refused"
	// codeRepairCodeNone: no repair code is waiting.
	codeRepairCodeNone = "repair_code_none"
	// codeRepairCodeWrong: the repair code is not the waiting one.
	codeRepairCodeWrong = "repair_code_wrong"
	// codeRepairCodeBody: the code was not sent as the one field of a small
	// JSON body (in the query string, an empty body, a body over 1 KiB).
	codeRepairCodeBody = "repair_code_body"
	// codeRepairUnavailable: this api has no break-glass service wired.
	codeRepairUnavailable = "repair_unavailable"
	// codeRepairSessionRequired: a repair route was asked for with no live
	// repair session at this origin.
	codeRepairSessionRequired = "repair_session_required"
	// codeRepairCookieDuplicate: the repair cookie was sent twice.
	codeRepairCookieDuplicate = "repair_cookie_duplicate"
	// codeRepairOnly: a console route was asked for with a live repair
	// session, which can only repair sign-in.
	codeRepairOnly = "repair_only"
	// codeJobUnavailable: the runner has no workflow for the job's kind on
	// this control plane, so no job was created.
	codeJobUnavailable = "job_unavailable"
	// codeJobStartFailed: a job the runner can run couldn't be recorded or
	// started (a failed ledger write, a cancelled request), so no job was
	// created; trying again may work.
	codeJobStartFailed = "job_start_failed"
)

// codedError is the body of a coded error. "error" stays a plain string, as
// every other response here has it, because the UI reads body.error as one
// (ui/lib/api.ts); code and correlationId sit beside it.
type codedError struct {
	Error         string `json:"error"`
	Code          string `json:"code"`
	CorrelationID string `json:"correlationId"`
}

// writeCodedError answers status with a stable code, a safe message and a
// correlation id, and logs a WARN record under that id carrying the route, the
// code and cause — the internal detail, which never reaches the client.
//
// The route is the pattern the request matched ("GET /api/bus/tls"), never
// the path the client sent, so nothing a caller types reaches the log.
func (s *Server) writeCodedError(w http.ResponseWriter, r *http.Request, status int, code, msg string, cause ...slog.Attr) {
	id := s.newCorrelationID()
	logRefusal(r.Context(), s.log, id, r.Pattern, code, cause...)
	writeCodedBody(w, status, code, msg, id)
}

// logRefusal is the one refusal record: a WARN under the correlation id,
// carrying the route, the code and cause. writeCodedError and the :443 site
// dispatcher (sites.go) both write it.
//
// CodeQL reports go/log-injection at the LogAttrs call below; the register
// (.github/codeql-register.tsv) records it as a false positive. Every value a
// caller passes in cause is written through log, which the composition root
// builds with logkit.New for both NewServer and NewSites: its slog.TextHandler
// quotes any value that needs it and escapes control characters, so no
// attribute can forge a record. The verdict holds while every logger passed
// here is logkit.New's.
func logRefusal(ctx context.Context, log *slog.Logger, id, route, code string, cause ...slog.Attr) {
	attrs := append([]slog.Attr{
		slog.String("correlation_id", id),
		slog.String("route", route),
		slog.String("code", code),
	}, cause...)
	log.LogAttrs(ctx, slog.LevelWarn, "api: request refused", attrs...)
}

// writeCodedBody writes the coded error body with status.
func writeCodedBody(w http.ResponseWriter, status int, code, msg, id string) {
	writeJSON(w, status, codedError{Error: msg, Code: code, CorrelationID: id})
}
