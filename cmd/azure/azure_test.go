// Copyright © 2024 BoxBoat
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

package azure

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"text/template"

	"github.com/Azure/azure-sdk-for-go/profiles/2019-03-01/keyvault/keyvault"
	"github.com/boxboat/dockcmd/cmd/common"
)

type mockGetSecretValueAPI func(ctx context.Context, vaultBaseURL string, secretName string, secretVersion string) (result keyvault.SecretBundle, err error)

func (m mockGetSecretValueAPI) GetSecret(ctx context.Context, vaultBaseURL string, secretName string, secretVersion string) (result keyvault.SecretBundle, err error) {
	return m(ctx, vaultBaseURL, secretName, secretVersion)
}

func TestSecretsClient_GetTextSecret(t *testing.T) {
	cases := []struct {
		client       func(t *testing.T) KeyVaultGetSecretAPI
		useAltDelims bool
		expect       []byte
		data         []byte
	}{
		{
			client: func(t *testing.T) KeyVaultGetSecretAPI {
				return mockGetSecretValueAPI(func(ctx context.Context, vaultBaseURL string, secretName string, secretVersion string) (result keyvault.SecretBundle, err error) {
					t.Helper()
					if secretName == "" {
						t.Fatalf("expect secretName to not be empty")
					}
					secretString := ""
					if secretName == "alpha" {
						secretString = "charlie"
					}
					return keyvault.SecretBundle{
						Value: &secretString,
					}, nil
				})
			},
			useAltDelims: true,
			data: []byte(`
textTestAlt:
  alpha: {{<< (azureText "alpha") | squote >>}}
`),
			expect: []byte(`
textTestAlt:
  alpha: {{'charlie'}}
`),
		},
	}
	for i, tt := range cases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			ctx := context.TODO()
			client, err := NewSecretsClient(WithMockClient(tt.client(t)), WithContext(ctx))
			common.UseAlternateDelims = tt.useAltDelims
			if err != nil {
				t.Fatalf("expect no error, got %v", err)
			}
			funcMap := template.FuncMap{
				"azureText": client.GetTextSecret,
			}
			result, err := common.ParseSecretsTemplate(tt.data, funcMap)
			if e, a := tt.expect, result; bytes.Compare(e, a) != 0 {
				t.Errorf("expect %v, got %v", string(e), string(a))
			}
		})
	}
}

func TestSecretsClient_GetJSONSecret(t *testing.T) {
	cases := []struct {
		client       func(t *testing.T) KeyVaultGetSecretAPI
		useAltDelims bool
		expect       []byte
		data         []byte
	}{
		{
			client: func(t *testing.T) KeyVaultGetSecretAPI {
				return mockGetSecretValueAPI(func(ctx context.Context, vaultBaseURL string, secretName string, secretVersion string) (result keyvault.SecretBundle, err error) {
					t.Helper()
					if secretName == "" {
						t.Fatalf("expect secretName to not be empty")
					}
					secretString := ""
					if secretName == "alpha" {
						secretString = `{"bravo":"foo", "charlie":"bar"}`
					}
					return keyvault.SecretBundle{
						Value: &secretString,
					}, nil
				})
			},
			useAltDelims: false,
			data: []byte(`
jsonTest:
  bravo: {{ (azureJson "alpha" "bravo") | squote }}
  charlie: {{ (azureJson "alpha" "charlie") | quote }}
`),
			expect: []byte(`
jsonTest:
  bravo: 'foo'
  charlie: "bar"
`),
		},
	}
	for i, tt := range cases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			ctx := context.TODO()
			client, err := NewSecretsClient(WithMockClient(tt.client(t)), WithContext(ctx))
			common.UseAlternateDelims = tt.useAltDelims
			if err != nil {
				t.Fatalf("expect no error, got %v", err)
			}
			funcMap := template.FuncMap{
				"azureJson": client.GetJSONSecret,
			}
			result, err := common.ParseSecretsTemplate(tt.data, funcMap)
			if e, a := tt.expect, result; bytes.Compare(e, a) != 0 {
				t.Errorf("expect %v, got %v", string(e), string(a))
			}
		})
	}
}
