package signin

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

// KnownPages are the Keycloak 26.8.2 login page ids the client knows, each
// with the step it is: geekdojo/geekdojo-brain#959's kcpages.KNOWN_PAGES, one
// fixture per id in testdata/pages/. Any other id is an *UnknownPageError.
var KnownPages = map[string]string{
	"login-login":                            "sign-in form",
	"login-register":                         "registration form",
	"login-login-otp":                        "authenticator code",
	"login-webauthn-authenticate":            "second-step passkey",
	"login-webauthn-error":                   "passkey refused",
	"login-webauthn-register":                "passkey enrolment",
	"login-select-authenticator":             "another way to sign in",
	"login-login-recovery-authn-code-input":  "recovery code",
	"login-login-recovery-authn-code-config": "recovery code enrolment",
	"login-login-config-totp":                "authenticator app enrolment",
	"login-login-update-password":            "new password",
	"login-error":                            "error",
}

// Page is one parsed login page: its id, its forms, and the feedback
// sentence a person reads on it, if any.
type Page struct {
	ID    string
	Forms []Form
	Alert string
}

// Form is one <form>: its id, action and method, and its named inputs with
// their values. Buttons, submit inputs and unchecked boxes are left out, and
// a name's first value wins, as a browser's submission of the form would
// carry.
type Form struct {
	ID, Action, Method string
	Fields             map[string]string
}

// Form returns the page's form with that id.
func (p Page) Form(id string) (Form, bool) {
	for _, f := range p.Forms {
		if f.ID == id {
			return f, true
		}
	}
	return Form{}, false
}

// UnknownPageError is a page whose id the client does not know: it refuses
// to guess what the page is.
type UnknownPageError struct{ ID string }

func (e *UnknownPageError) Error() string {
	return fmt.Sprintf("signin: the page %s is not one the client knows", e.ID)
}

// ErrNoPageID is a page whose body carries no data-page-id.
var ErrNoPageID = errors.New("signin: the page has no data-page-id, so the client cannot tell which page it is")

// alertIDs are the elements whose text is the page's feedback sentence, in
// #959's order (kcpages.message).
var alertIDs = []string{"kc-error-message", "input-error", "input-error-username", "input-error-otp-code"}

// ParsePage reads a login page: the body's data-page-id first, refusing an
// unknown or missing one, then its forms and its feedback sentence.
func ParsePage(body []byte) (Page, error) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return Page{}, fmt.Errorf("signin: parse the page: %w", err)
	}
	var page Page
	var bodyFound bool
	textByID := map[string]string{}
	feedback := ""
	var cur *Form
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "body":
				if !bodyFound {
					bodyFound = true
					page.ID = attr(n, "data-page-id")
				}
			case "form":
				page.Forms = append(page.Forms, Form{
					ID: attr(n, "id"), Action: attr(n, "action"),
					Method: strings.ToLower(attrOr(n, "method", "get")), Fields: map[string]string{},
				})
				cur = &page.Forms[len(page.Forms)-1]
				defer func() { cur = nil }()
			case "input", "textarea", "select":
				addField(cur, n)
			}
			if id := attr(n, "id"); id != "" {
				if _, seen := textByID[id]; !seen {
					textByID[id] = text(n)
				}
			}
			if feedback == "" && strings.Contains(" "+attr(n, "class")+" ", " kc-feedback-text ") {
				feedback = text(n)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	if page.ID == "" {
		return Page{}, ErrNoPageID
	}
	if _, ok := KnownPages[page.ID]; !ok {
		return Page{}, &UnknownPageError{ID: page.ID}
	}
	for _, id := range alertIDs {
		if t := textByID[id]; t != "" {
			page.Alert = t
			break
		}
	}
	if page.Alert == "" {
		page.Alert = feedback
	}
	return page, nil
}

// addField records a named input of the form being read, as kcpages does.
func addField(f *Form, n *html.Node) {
	if f == nil {
		return
	}
	name := attr(n, "name")
	if name == "" {
		return
	}
	kind := strings.ToLower(attr(n, "type"))
	if (kind == "checkbox" || kind == "radio") && !hasAttr(n, "checked") {
		return
	}
	if kind == "submit" {
		return
	}
	if _, ok := f.Fields[name]; !ok {
		f.Fields[name] = attr(n, "value")
	}
}

func attr(n *html.Node, key string) string { return attrOr(n, key, "") }

func attrOr(n *html.Node, key, def string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			if a.Val == "" {
				return def
			}
			return a.Val
		}
	}
	return def
}

func hasAttr(n *html.Node, key string) bool {
	for _, a := range n.Attr {
		if a.Key == key {
			return true
		}
	}
	return false
}

// text is a node's text with runs of white space collapsed.
func text(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			b.WriteByte(' ')
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}
