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

package gcp

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"text/template"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/googleapis/gax-go/v2"
)

type mockGetSecretValueAPI func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)

func (m mockGetSecretValueAPI) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return m(ctx, req, opts...)
}

func TestSecretsClient_GetTextSecret(t *testing.T) {
	cases := []struct {
		client       func(t *testing.T) SecretsManagerGetSecretAPI
		useAltDelims bool
		expect       []byte
		data         []byte
	}{
		{
			client: func(t *testing.T) SecretsManagerGetSecretAPI {
				return mockGetSecretValueAPI(func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
					t.Helper()
					if req.GetName() == "" {
						t.Fatalf("expect reqName to not be empty")
					}
					secretString := ""
					if req.GetName() == "projects/test/secrets/alpha/versions/latest" {
						secretString = "charlie"
					}
					return &secretmanagerpb.AccessSecretVersionResponse{
						Payload: &secretmanagerpb.SecretPayload{
							Data: []byte(secretString),
						},
					}, nil
				})
			},
			useAltDelims: true,
			data: []byte(`
textTestAlt:
  alpha: {{<< (gcpText "alpha") | squote >>}}
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
			client, err := NewSecretsClient(WithMockClient(tt.client(t)), WithContext(ctx), Project("test"))
			common.UseAlternateDelims = tt.useAltDelims
			if err != nil {
				t.Fatalf("expect no error, got %v", err)
			}
			funcMap := template.FuncMap{
				"gcpText": client.GetTextSecret,
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
		client       func(t *testing.T) SecretsManagerGetSecretAPI
		useAltDelims bool
		expect       []byte
		data         []byte
	}{
		{
			client: func(t *testing.T) SecretsManagerGetSecretAPI {
				return mockGetSecretValueAPI(func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
					t.Helper()
					if req.GetName() == "" {
						t.Fatalf("expect reqName to not be empty")
					}
					secretString := ""
					if req.GetName() == "projects/test/secrets/alpha/versions/latest" {
						secretString = `{"bravo":"foo", "charlie":"bar"}`
					}
					return &secretmanagerpb.AccessSecretVersionResponse{
						Payload: &secretmanagerpb.SecretPayload{
							Data: []byte(secretString),
						},
					}, nil
				})
			},
			useAltDelims: false,
			data: []byte(`
jsonTest:
  bravo: {{ (gcpJson "alpha" "bravo") | squote }}
  charlie: {{ (gcpJson "alpha" "charlie") | quote }}
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
			client, err := NewSecretsClient(WithMockClient(tt.client(t)), WithContext(ctx), Project("test"))
			common.UseAlternateDelims = tt.useAltDelims
			if err != nil {
				t.Fatalf("expect no error, got %v", err)
			}
			funcMap := template.FuncMap{
				"gcpJson": client.GetJSONSecret,
			}
			result, err := common.ParseSecretsTemplate(tt.data, funcMap)
			if e, a := tt.expect, result; bytes.Compare(e, a) != 0 {
				t.Errorf("expect %v, got %v", string(e), string(a))
			}
		})
	}
}
