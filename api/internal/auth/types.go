package auth

import (
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// User is the api's view of a Rasputin user. Implements webauthn.User.
type User struct {
	ID          []byte     `json:"id"`
	Name        string     `json:"name"`
	DisplayName string     `json:"displayName"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
	// credentials is loaded eagerly by the store for WebAuthn flows.
	credentials []webauthn.Credential
}

// WebAuthnID implements webauthn.User.
func (u *User) WebAuthnID() []byte { return u.ID }

// WebAuthnName implements webauthn.User.
func (u *User) WebAuthnName() string { return u.Name }

// WebAuthnDisplayName implements webauthn.User.
func (u *User) WebAuthnDisplayName() string {
	if u.DisplayName == "" {
		return u.Name
	}
	return u.DisplayName
}

// WebAuthnCredentials implements webauthn.User.
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// Credential is the persisted form of a WebAuthn credential. Stored in the
// credentials table; mapped to/from webauthn.Credential at the boundary.
type Credential struct {
	ID              []byte                            `json:"id"`
	UserID          []byte                            `json:"userId"`
	PublicKey       []byte                            `json:"-"`
	AttestationType string                            `json:"attestationType"`
	Transports      []protocol.AuthenticatorTransport `json:"transports"`
	AAGUID          []byte                            `json:"aaguid"`
	SignCount       uint32                            `json:"signCount"`
	CloneWarning    bool                              `json:"cloneWarning"`
	// BackupEligible (BE) is set at registration and must NOT change across
	// authentications — the library aborts login if it does.
	BackupEligible bool `json:"backupEligible"`
	// BackupState (BS) reflects whether the credential is currently backed
	// up. It may legitimately flip true/false over time; we refresh it on
	// every login.
	BackupState bool       `json:"backupState"`
	Nickname    string     `json:"nickname"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
}

func (c *Credential) toWebAuthn() webauthn.Credential {
	return webauthn.Credential{
		ID:              c.ID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       c.Transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       c.AAGUID,
			SignCount:    c.SignCount,
			CloneWarning: c.CloneWarning,
		},
	}
}

func fromWebAuthn(cred *webauthn.Credential, userID []byte) *Credential {
	return &Credential{
		ID:              cred.ID,
		UserID:          userID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Transports:      cred.Transport,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		CloneWarning:    cred.Authenticator.CloneWarning,
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
	}
}

func encodeTransports(t []protocol.AuthenticatorTransport) string {
	if len(t) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(t)
	return string(b)
}

func decodeTransports(s string) []protocol.AuthenticatorTransport {
	var t []protocol.AuthenticatorTransport
	_ = json.Unmarshal([]byte(s), &t)
	return t
}

// Session is an opaque server-side session token bound to a user. The token
// itself is the cookie value sent to the browser.
type Session struct {
	Token        string    `json:"-"`
	UserID       []byte    `json:"userId"`
	CreatedAt    time.Time `json:"createdAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
	LastActiveAt time.Time `json:"lastActiveAt"`
}
