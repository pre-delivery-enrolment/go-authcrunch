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
	"crypto/sha256"
	"encoding/base64"
)

// pkceCharset is the unreserved character set defined in RFC 7636 Section 4.1.
// It contains exactly 66 characters: A-Z, a-z, 0-9, and the four symbols - . _ ~
const pkceCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// pkceVerifierLength is the fixed length of a generated code verifier.
const pkceVerifierLength = 96

// GenerateCodeVerifier returns a 96-character cryptographically random string
// using the RFC 7636 Section 4.1 unreserved charset. Character selection is
// bias-free: genRandInt uses crypto/rand.Int for uniform distribution over the
// charset length (66), which is not a power of two.
func GenerateCodeVerifier() string {
	b := make([]byte, pkceVerifierLength)
	for i := range b {
		b[i] = pkceCharset[genRandInt(len(pkceCharset))]
	}
	return string(b)
}

// ComputeCodeChallenge computes BASE64URL(SHA256(code_verifier)) with no
// padding, as specified in RFC 7636 Section 4.2. The result is always 43
// characters long.
func ComputeCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
