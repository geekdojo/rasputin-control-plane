package secretstore_test

import (
	"errors"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
)

// TC-759-15: Mock.CertLogin returns a non-empty token for a role and refuses
// an empty one as ErrInvalidValue; Disabled.CertLogin is ErrDisabled with
// Op=login and no I/O.
func TestCertLogin_MockAndDisabled(t *testing.T) {
	m := secretstore.NewMock(time.Now)
	tok, err := m.CertLogin(t.Context(), "rasputin-api")
	if err != nil || tok.Len() == 0 {
		t.Fatalf("Mock.CertLogin(rasputin-api) = %d bytes, %v; want a non-empty token", tok.Len(), err)
	}
	tok, err = m.CertLogin(t.Context(), "")
	var se *secretstore.Error
	if !errors.Is(err, secretstore.ErrInvalidValue) || !errors.As(err, &se) || se.Op != "login" || tok.Len() != 0 {
		t.Errorf("Mock.CertLogin(\"\") = %d bytes, %v; want ErrInvalidValue with Op=login", tok.Len(), err)
	}

	tok, err = secretstore.Disabled{}.CertLogin(t.Context(), "rasputin-api")
	se = nil
	if !errors.Is(err, secretstore.ErrDisabled) || !errors.As(err, &se) || se.Op != "login" || tok.Len() != 0 {
		t.Errorf("Disabled.CertLogin = %d bytes, %v; want ErrDisabled with Op=login", tok.Len(), err)
	}
}
