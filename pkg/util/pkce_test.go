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

package util

import (
	"strings"
	"testing"
)

func TestGenerateCodeVerifier(t *testing.T) {
	t.Run("returns exactly 96 characters", func(t *testing.T) {
		v := GenerateCodeVerifier()
		if len(v) != 96 {
			t.Errorf("expected length 96, got %d", len(v))
		}
	})

	t.Run("uses only RFC 7636 unreserved characters", func(t *testing.T) {
		v := GenerateCodeVerifier()
		for i, ch := range v {
			if !strings.ContainsRune(pkceCharset, ch) {
				t.Errorf("invalid character %q at position %d", ch, i)
			}
		}
	})

	t.Run("produces different values on consecutive calls", func(t *testing.T) {
		a := GenerateCodeVerifier()
		b := GenerateCodeVerifier()
		if a == b {
			t.Error("two consecutive verifiers are identical; randomness check failed")
		}
	})
}

func TestComputeCodeChallenge(t *testing.T) {
	t.Run("returns exactly 43 characters", func(t *testing.T) {
		challenge := ComputeCodeChallenge(GenerateCodeVerifier())
		if len(challenge) != 43 {
			t.Errorf("expected length 43, got %d", len(challenge))
		}
	})

	// RFC 7636 Appendix B test vector.
	t.Run("matches RFC 7636 Appendix B test vector", func(t *testing.T) {
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
		got := ComputeCodeChallenge(verifier)
		if got != want {
			t.Errorf("challenge mismatch\n  got:  %s\n  want: %s", got, want)
		}
	})
}
