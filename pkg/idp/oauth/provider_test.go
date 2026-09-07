// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/util"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestNewIdentityProvider(t *testing.T) {
	// Generate JWKS keys from RSA key-pairs.
	pk1, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	jpk1, err := NewJwksKeyFromRSAPrivateKey(pk1)
	if err != nil {
		t.Fatal(err)
	}

	jpk2, err := NewJwksKeyFromRSAPrivateKey(pk2)
	if err != nil {
		t.Fatal(err)
	}

	jwksKeys := []*JwksKey{jpk1, jpk2}

	// Initialize HTTP server.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := make(map[string]interface{})
		switch r.URL.Path {
		case "/oauth/.well-known/openid-configuration":
			resp["authorization_endpoint"] = "https://" + r.Host + "/oauth/authorize"
			resp["token_endpoint"] = "https://" + r.Host + "/oauth/access_token"
			resp["jwks_uri"] = "https://" + r.Host + "/oauth/jwks.json"
		case "/oauth/jwks.json":
			resp["keys"] = jwksKeys
		default:
			t.Fatalf("unsupported path: %v", r.URL.Path)
		}

		b, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("failed to marshal %T: %v", resp, err)
		}

		fmt.Fprintln(w, string(b))
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	// t.Logf("Server: %s", ts.URL)

	testcases := []struct {
		name      string
		config    *Config
		logger    *zap.Logger
		want      map[string]interface{}
		shouldErr bool
		errPhase  string
		err       error
	}{
		{
			name: "generic oauth provider",
			config: &Config{
				Name:                  "contoso",
				Realm:                 "contoso",
				Driver:                "generic",
				ClientID:              "foo",
				ClientSecret:          "bar",
				BaseAuthURL:           ts.URL + "/oauth",
				MetadataURL:           ts.URL + "/oauth/.well-known/openid-configuration",
				TLSInsecureSkipVerify: true,
			},
			logger: logutil.NewLogger(),
			want: map[string]interface{}{
				"kind":  "oauth",
				"name":  "contoso",
				"realm": "contoso",
				"config": map[string]interface{}{
					"base_auth_url":            ts.URL + "/oauth",
					"client_id":                "foo",
					"client_secret":            "bar",
					"driver":                   "generic",
					"identity_token_name":      "id_token",
					"metadata_url":             ts.URL + "/oauth/.well-known/openid-configuration",
					"name":                     "contoso",
					"realm":                    "contoso",
					"required_token_fields":    []interface{}{"access_token", "id_token"},
					"response_type":            []interface{}{"code"},
					"scopes":                   []interface{}{"openid", "email", "profile"},
					"server_name":              tsURL.Host,
					"tls_insecure_skip_verify": bool(true),
					"token_leeway":             float64(30),
					"login_icon": map[string]interface{}{
						"background_color": string("#324960"),
						"class_name":       string("lab la-codepen la-2x"),
						"color":            string("white"),
						"text_color":       string("#37474f"),
					},
				},
			},
		},
		{
			name: "generic oauth provider with static jwks keys",
			config: &Config{
				Name:                "contoso",
				Realm:               "contoso",
				Driver:              "generic",
				ClientID:            "foo",
				ClientSecret:        "bar",
				BaseAuthURL:         "https://localhost/oauth",
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token"},
				AuthorizationURL:    "https://localhost/oauth/authorize",
				TokenURL:            "https://localhost/oauth/access_token",
				JwksKeys: map[string]string{
					"87329db33bf": "../../../testdata/oauth/87329db33bf_pub.pem",
				},
				KeyVerificationDisabled: true,
				TLSInsecureSkipVerify:   true,
			},
			logger: logutil.NewLogger(),
			want: map[string]interface{}{
				"kind":  "oauth",
				"name":  "contoso",
				"realm": "contoso",
				"config": map[string]interface{}{
					"base_auth_url":             "https://localhost/oauth",
					"token_url":                 "https://localhost/oauth/access_token",
					"authorization_url":         "https://localhost/oauth/authorize",
					"client_id":                 "foo",
					"client_secret":             "bar",
					"driver":                    "generic",
					"identity_token_name":       "id_token",
					"name":                      "contoso",
					"realm":                     "contoso",
					"required_token_fields":     []interface{}{"access_token"},
					"response_type":             []interface{}{"code"},
					"scopes":                    []interface{}{"openid", "email", "profile"},
					"server_name":               "localhost",
					"tls_insecure_skip_verify":  true,
					"key_verification_disabled": true,
					"token_leeway":              float64(30),
					"jwks_keys": map[string]interface{}{
						"87329db33bf": "../../../testdata/oauth/87329db33bf_pub.pem",
					},
					"login_icon": map[string]interface{}{
						"background_color": string("#324960"),
						"class_name":       string("lab la-codepen la-2x"),
						"color":            string("white"),
						"text_color":       string("#37474f"),
					},
				},
			},
		},
		{
			name: "test nil logger",
			config: &Config{
				Realm: "azure",
			},
			shouldErr: true,
			errPhase:  "initialize",
			err:       errors.ErrIdentityProviderConfigureLoggerNotFound,
		},
		{
			name: "test invalid config",
			config: &Config{
				Realm: "azure",
			},
			logger:    logutil.NewLogger(),
			shouldErr: true,
			errPhase:  "initialize",
			err:       errors.ErrIdentityProviderConfigureNameEmpty,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))

			prv, err := NewIdentityProvider(tc.config, tc.logger)
			if tc.errPhase == "initialize" {
				if tests.EvalErrWithLog(t, err, "NewIdentityProvider", tc.shouldErr, tc.err, msgs) {
					return
				}
			} else {
				if tests.EvalErrWithLog(t, err, "NewIdentityProvider", false, nil, msgs) {
					return
				}
			}

			err = prv.Configure()
			if tc.errPhase == "configure" {
				if tests.EvalErrWithLog(t, err, "IdentityProvider.Configure", tc.shouldErr, tc.err, msgs) {
					return
				}
			} else {
				if tests.EvalErrWithLog(t, err, "IdentityProvider.Configure", false, nil, msgs) {
					return
				}
			}

			got["name"] = prv.GetName()
			got["realm"] = prv.GetRealm()
			got["kind"] = prv.GetKind()
			got["config"] = prv.GetConfig()

			tests.EvalObjectsWithLog(t, "IdentityProvider", tc.want, got, msgs)
		})
	}
}

func TestPKCEFlow(t *testing.T) {
	// 2048-bit RSA key is sufficient for tests and much faster than 4096-bit.
	pk1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jpk1, err := NewJwksKeyFromRSAPrivateKey(pk1)
	if err != nil {
		t.Fatal(err)
	}

	jwksKeys := []*JwksKey{jpk1}

	// capturedCodeVerifier is written by the mock token endpoint handler and
	// read by sub-test 2.  redirectNonce is written by sub-test 1 and read by
	// the token endpoint handler when it builds the id_token JWT.
	var (
		capturedCodeVerifier string
		redirectNonce        string
	)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		resp := make(map[string]interface{})
		switch req.URL.Path {
		case "/.well-known/openid-configuration":
			resp["authorization_endpoint"] = "https://" + req.Host + "/authorize"
			resp["token_endpoint"] = "https://" + req.Host + "/access_token"
			resp["jwks_uri"] = "https://" + req.Host + "/jwks.json"
		case "/jwks.json":
			resp["keys"] = jwksKeys
		case "/access_token":
			if parseErr := req.ParseForm(); parseErr != nil {
				t.Errorf("mock /access_token: failed to parse form: %v", parseErr)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			capturedCodeVerifier = req.FormValue("code_verifier")

			now := time.Now()
			claims := jwtlib.MapClaims{
				"sub":   "test-user",
				"email": "test@example.com",
				"nonce": redirectNonce,
				"iat":   float64(now.Unix()),
				"exp":   float64(now.Add(time.Hour).Unix()),
			}
			idToken := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
			idTokenStr, signErr := idToken.SignedString(pk1)
			if signErr != nil {
				t.Errorf("mock /access_token: failed to sign id_token: %v", signErr)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			resp["access_token"] = "test_access_token"
			resp["id_token"] = idTokenStr
		default:
			t.Fatalf("mock server: unsupported path: %v", req.URL.Path)
		}

		b, marshalErr := json.Marshal(resp)
		if marshalErr != nil {
			t.Fatalf("mock server: failed to marshal response: %v", marshalErr)
		}
		fmt.Fprintln(w, string(b))
	}))
	defer ts.Close()

	logger := logutil.NewLogger()

	prv, err := NewIdentityProvider(&Config{
		Name:                  "contoso",
		Realm:                 "contoso",
		Driver:                "generic",
		ClientID:              "foo",
		ClientSecret:          "bar",
		BaseAuthURL:           ts.URL,
		MetadataURL:           ts.URL + "/.well-known/openid-configuration",
		TLSInsecureSkipVerify: true,
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := prv.Configure(); err != nil {
		t.Fatal(err)
	}
	prv.disablePKCE = false // Enable PKCE for testing the PKCE flow mechanics

	// redirectState and redirectChallenge are set by sub-test 1 and consumed by
	// sub-test 2.  Sub-tests run sequentially (no t.Parallel), so plain
	// variables are safe.
	var redirectState, redirectChallenge string

	t.Run("PKCE params present in authorization redirect", func(t *testing.T) {
		reqURL, _ := url.Parse(
			"https://auth.example.com/callback?redirect_url=https%3A%2F%2Fauth.example.com%2Flogin",
		)
		r := &requests.Request{
			ID: "test-1",
			Upstream: requests.Upstream{
				Request:   &http.Request{URL: reqURL},
				BaseURL:   "https://auth.example.com",
				BasePath:  "/",
				Method:    "oauth2",
				Realm:     "contoso",
				SessionID: "session-1",
			},
		}

		if err := prv.Authenticate(r); err != nil {
			t.Fatalf("Authenticate returned unexpected error: %v", err)
		}
		if r.Response.Code != http.StatusFound {
			t.Fatalf("expected response code 302, got %d", r.Response.Code)
		}

		parsed, err := url.Parse(r.Response.RedirectURL)
		if err != nil {
			t.Fatalf("failed to parse redirect URL %q: %v", r.Response.RedirectURL, err)
		}
		q := parsed.Query()

		challenge := q.Get("code_challenge")
		if challenge == "" {
			t.Fatal("code_challenge not present in redirect URL")
		}
		if len(challenge) != 43 {
			t.Fatalf("code_challenge length = %d, want 43", len(challenge))
		}
		if method := q.Get("code_challenge_method"); method != "S256" {
			t.Fatalf("code_challenge_method = %q, want S256", method)
		}
		state := q.Get("state")
		if state == "" {
			t.Fatal("state not present in redirect URL")
		}

		redirectState = state
		redirectChallenge = challenge
		redirectNonce = q.Get("nonce")
	})

	t.Run("code_verifier sent in token exchange", func(t *testing.T) {
		if redirectState == "" {
			t.Skip("skipping: sub-test 1 did not produce a redirect state")
		}

		callbackURL, _ := url.Parse(
			"https://auth.example.com/callback?code=test_code&state=" +
				url.QueryEscape(redirectState),
		)
		r := &requests.Request{
			ID: "test-2",
			Upstream: requests.Upstream{
				Request:   &http.Request{URL: callbackURL},
				BaseURL:   "https://auth.example.com",
				BasePath:  "/",
				Method:    "oauth2",
				Realm:     "contoso",
				SessionID: "session-2",
			},
		}

		if err := prv.Authenticate(r); err != nil {
			t.Fatalf("Authenticate (callback) returned error: %v", err)
		}
		if r.Response.Code != http.StatusOK {
			t.Fatalf("expected response code 200, got %d", r.Response.Code)
		}
		if capturedCodeVerifier == "" {
			t.Fatal("code_verifier was not sent to the token endpoint")
		}
		if got := util.ComputeCodeChallenge(capturedCodeVerifier); got != redirectChallenge {
			t.Fatalf("PKCE mismatch: ComputeCodeChallenge(%q) = %q, want %q",
				capturedCodeVerifier, got, redirectChallenge)
		}
	})

	t.Run("PKCE params absent when disabled", func(t *testing.T) {
		prvNoPKCE, err := NewIdentityProvider(&Config{
			Name:                  "contoso2",
			Realm:                 "contoso2",
			Driver:                "generic",
			ClientID:              "foo",
			ClientSecret:          "bar",
			BaseAuthURL:           ts.URL,
			MetadataURL:           ts.URL + "/.well-known/openid-configuration",
			TLSInsecureSkipVerify: true,
			PKCEDisabled:          true,
		}, logger)
		if err != nil {
			t.Fatal(err)
		}
		if err := prvNoPKCE.Configure(); err != nil {
			t.Fatal(err)
		}

		reqURL, _ := url.Parse(
			"https://auth.example.com/callback?redirect_url=https%3A%2F%2Fauth.example.com%2Flogin",
		)
		r := &requests.Request{
			ID: "test-3",
			Upstream: requests.Upstream{
				Request:   &http.Request{URL: reqURL},
				BaseURL:   "https://auth.example.com",
				BasePath:  "/",
				Method:    "oauth2",
				Realm:     "contoso2",
				SessionID: "session-3",
			},
		}

		if err := prvNoPKCE.Authenticate(r); err != nil {
			t.Fatalf("Authenticate returned unexpected error: %v", err)
		}
		if r.Response.Code != http.StatusFound {
			t.Fatalf("expected response code 302, got %d", r.Response.Code)
		}

		parsed, err := url.Parse(r.Response.RedirectURL)
		if err != nil {
			t.Fatalf("failed to parse redirect URL: %v", err)
		}
		q := parsed.Query()

		if v := q.Get("code_challenge"); v != "" {
			t.Errorf("code_challenge should be absent when PKCE is disabled, got %q", v)
		}
		if v := q.Get("code_challenge_method"); v != "" {
			t.Errorf("code_challenge_method should be absent when PKCE is disabled, got %q", v)
		}
	})
}
