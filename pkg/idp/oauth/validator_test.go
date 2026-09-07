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
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
)

func TestValidateAccessTokenCariadEmail(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jpk, err := NewJwksKeyFromRSAPrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	prv := &IdentityProvider{
		config: &Config{
			IdentityTokenName: "id_token",
		},
		keys:   map[string]*JwksKey{jpk.KeyID: jpk},
		state:  newStateManager(),
		logger: logutil.NewLogger(),
	}
	go manageStateManager(prv.state)

	buildToken := func(claims jwtlib.MapClaims) string {
		token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
		token.Header["kid"] = jpk.KeyID
		signed, signErr := token.SignedString(pk)
		if signErr != nil {
			t.Fatalf("failed to sign token: %v", signErr)
		}
		return signed
	}

	now := time.Now()

	t.Run("cariad_email normalized to email when email absent", func(t *testing.T) {
		prv.state.add("state-1", "nonce-1", "")

		signed := buildToken(jwtlib.MapClaims{
			"sub":          "user-sub-1",
			"name":         "Test User",
			"cariad_email": "user@cariad.example",
			"nonce":        "nonce-1",
			"iat":          float64(now.Unix()),
			"exp":          float64(now.Add(time.Hour).Unix()),
		})

		result, err := prv.validateAccessToken("state-1", map[string]interface{}{
			"id_token": signed,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result["email"] != "user@cariad.example" {
			t.Errorf("email = %q, want %q", result["email"], "user@cariad.example")
		}
		if result["sub"] != "user-sub-1" {
			t.Errorf("sub = %q, want %q", result["sub"], "user-sub-1")
		}
		if result["name"] != "Test User" {
			t.Errorf("name = %q, want %q", result["name"], "Test User")
		}
	})

	t.Run("email takes precedence over cariad_email", func(t *testing.T) {
		prv.state.add("state-2", "nonce-2", "")

		signed := buildToken(jwtlib.MapClaims{
			"sub":          "user-sub-2",
			"name":         "Test User Two",
			"email":        "standard@example.com",
			"cariad_email": "cariad@example.com",
			"nonce":        "nonce-2",
			"iat":          float64(now.Unix()),
			"exp":          float64(now.Add(time.Hour).Unix()),
		})

		result, err := prv.validateAccessToken("state-2", map[string]interface{}{
			"id_token": signed,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result["email"] != "standard@example.com" {
			t.Errorf("email = %q, want %q", result["email"], "standard@example.com")
		}
	})

	t.Run("error when neither email nor cariad_email present", func(t *testing.T) {
		prv.state.add("state-3", "nonce-3", "")
		prv.disableEmailClaimCheck = false

		signed := buildToken(jwtlib.MapClaims{
			"sub":   "user-sub-3",
			"name":  "Test User Three",
			"nonce": "nonce-3",
			"iat":   float64(now.Unix()),
			"exp":   float64(now.Add(time.Hour).Unix()),
		})

		_, err := prv.validateAccessToken("state-3", map[string]interface{}{
			"id_token": signed,
		})
		if err == nil {
			t.Fatal("expected error but got nil")
		}
	})
}

func TestValidateAccessTokenLeeway(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jpk, err := NewJwksKeyFromRSAPrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	prv := &IdentityProvider{
		config: &Config{
			IdentityTokenName: "id_token",
		},
		keys:        map[string]*JwksKey{jpk.KeyID: jpk},
		state:       newStateManager(),
		logger:      logutil.NewLogger(),
		tokenLeeway: 30 * time.Second,
	}
	go manageStateManager(prv.state)

	buildToken := func(claims jwtlib.MapClaims) string {
		token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
		token.Header["kid"] = jpk.KeyID
		signed, signErr := token.SignedString(pk)
		if signErr != nil {
			t.Fatalf("failed to sign token: %v", signErr)
		}
		return signed
	}

	t.Run("iat 29s in future is accepted within 30s leeway", func(t *testing.T) {
		prv.state.add("leeway-state-1", "leeway-nonce-1", "")
		now := time.Now()
		signed := buildToken(jwtlib.MapClaims{
			"sub":   "user-leeway-1",
			"email": "user@example.com",
			"nonce": "leeway-nonce-1",
			"iat":   float64(now.Add(29 * time.Second).Unix()),
			"exp":   float64(now.Add(time.Hour).Unix()),
		})
		_, err := prv.validateAccessToken("leeway-state-1", map[string]interface{}{
			"id_token": signed,
		})
		if err != nil {
			t.Fatalf("expected token with iat 29s in future to be accepted within 30s leeway, got error: %v", err)
		}
	})

	t.Run("iat 31s in future is rejected beyond 30s leeway", func(t *testing.T) {
		prv.state.add("leeway-state-2", "leeway-nonce-2", "")
		now := time.Now()
		signed := buildToken(jwtlib.MapClaims{
			"sub":   "user-leeway-2",
			"email": "user@example.com",
			"nonce": "leeway-nonce-2",
			"iat":   float64(now.Add(31 * time.Second).Unix()),
			"exp":   float64(now.Add(time.Hour).Unix()),
		})
		_, err := prv.validateAccessToken("leeway-state-2", map[string]interface{}{
			"id_token": signed,
		})
		if err == nil {
			t.Fatal("expected token with iat 31s in future to be rejected, got nil error")
		}
	})

	t.Run("exp 31s in past is rejected as expired beyond 30s leeway", func(t *testing.T) {
		prv.state.add("leeway-state-3", "leeway-nonce-3", "")
		now := time.Now()
		signed := buildToken(jwtlib.MapClaims{
			"sub":   "user-leeway-3",
			"email": "user@example.com",
			"nonce": "leeway-nonce-3",
			"iat":   float64(now.Add(-time.Hour).Unix()),
			"exp":   float64(now.Add(-31 * time.Second).Unix()),
		})
		_, err := prv.validateAccessToken("leeway-state-3", map[string]interface{}{
			"id_token": signed,
		})
		if err == nil {
			t.Fatal("expected token with exp 31s in past to be rejected, got nil error")
		}
	})
}
