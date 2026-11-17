package samlsp

import (
	"crypto"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml"
)

// bindingEndpointIDPMetadata returns IDP metadata whose SingleSignOnService
// endpoints are exactly endpoints.
func bindingEndpointIDPMetadata(endpoints ...saml.Endpoint) *saml.EntityDescriptor {
	return &saml.EntityDescriptor{
		EntityID: "https://idp.example.com/",
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SingleSignOnServices: endpoints,
		}},
	}
}

func bindingEndpointMiddleware(t *testing.T, binding string, idpMetadata *saml.EntityDescriptor) *Middleware {
	t.Helper()
	m, err := New(Options{
		URL:         mustParseURL("https://sp.example.com/"),
		Key:         mustParsePrivateKey(golden.Get(t, "key.pem")).(crypto.Signer),
		Certificate: mustParseCertificate(golden.Get(t, "cert.pem")),
		IDPMetadata: idpMetadata,
		Binding:     binding,
	})
	assert.NilError(t, err)
	return m
}

// An explicitly configured Binding the IDP metadata has no endpoint for
// must not start the auth flow: the AuthnRequest would have an empty
// Destination, and the HTTP-Redirect binding would send the browser to a
// relative URL on this SP, looping the login. HandleStartAuthFlow answers
// 500 instead, and never a redirect back to itself.
func TestHandleStartAuthFlowConfiguredBindingWithoutEndpoint(t *testing.T) {
	postOnly := bindingEndpointIDPMetadata(
		saml.Endpoint{Binding: saml.HTTPPostBinding, Location: "https://idp.example.com/sso/post"})
	redirectOnly := bindingEndpointIDPMetadata(
		saml.Endpoint{Binding: saml.HTTPRedirectBinding, Location: "https://idp.example.com/sso/redirect"})

	t.Run("redirect configured, metadata has only POST", func(t *testing.T) {
		m := bindingEndpointMiddleware(t, saml.HTTPRedirectBinding, postOnly)
		rec := httptest.NewRecorder()
		m.HandleStartAuthFlow(rec, httptest.NewRequest(http.MethodGet, "/frob", nil))
		assert.Check(t, is.Equal(http.StatusInternalServerError, rec.Code))
		assert.Check(t, is.Equal("", rec.Header().Get("Location")))
	})

	t.Run("POST configured, metadata has only redirect", func(t *testing.T) {
		m := bindingEndpointMiddleware(t, saml.HTTPPostBinding, redirectOnly)
		rec := httptest.NewRecorder()
		m.HandleStartAuthFlow(rec, httptest.NewRequest(http.MethodGet, "/frob", nil))
		assert.Check(t, is.Equal(http.StatusInternalServerError, rec.Code))
		assert.Check(t, is.Equal("", rec.Header().Get("Location")))
	})
}

// Without a configured Binding, HandleStartAuthFlow keeps discovering the
// binding from the IDP metadata: HTTP-Redirect when it has an endpoint,
// HTTP-POST otherwise, and a 500 when it has neither.
func TestHandleStartAuthFlowDiscoveredBinding(t *testing.T) {
	t.Run("metadata has only POST", func(t *testing.T) {
		m := bindingEndpointMiddleware(t, "", bindingEndpointIDPMetadata(
			saml.Endpoint{Binding: saml.HTTPPostBinding, Location: "https://idp.example.com/sso/post"}))
		rec := httptest.NewRecorder()
		m.HandleStartAuthFlow(rec, httptest.NewRequest(http.MethodGet, "/frob", nil))
		assert.Check(t, is.Equal(http.StatusOK, rec.Code))
		assert.Check(t, strings.Contains(rec.Body.String(), `action="https://idp.example.com/sso/post"`))
	})

	t.Run("metadata has only redirect", func(t *testing.T) {
		m := bindingEndpointMiddleware(t, "", bindingEndpointIDPMetadata(
			saml.Endpoint{Binding: saml.HTTPRedirectBinding, Location: "https://idp.example.com/sso/redirect"}))
		rec := httptest.NewRecorder()
		m.HandleStartAuthFlow(rec, httptest.NewRequest(http.MethodGet, "/frob", nil))
		assert.Check(t, is.Equal(http.StatusFound, rec.Code))
		assert.Check(t, strings.HasPrefix(rec.Header().Get("Location"), "https://idp.example.com/sso/redirect?"))
	})

	t.Run("metadata has no SSO endpoint", func(t *testing.T) {
		m := bindingEndpointMiddleware(t, "", bindingEndpointIDPMetadata())
		rec := httptest.NewRecorder()
		m.HandleStartAuthFlow(rec, httptest.NewRequest(http.MethodGet, "/frob", nil))
		assert.Check(t, is.Equal(http.StatusInternalServerError, rec.Code))
		assert.Check(t, is.Equal("", rec.Header().Get("Location")))
	})
}
