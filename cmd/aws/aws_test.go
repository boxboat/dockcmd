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

package aws

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"text/template"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/boxboat/dockcmd/cmd/common"
)

type mockGetSecretValueAPI func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(options *secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)

func (m mockGetSecretValueAPI) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(options *secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return m(ctx, params, optFns...)
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
				return mockGetSecretValueAPI(func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(options *secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
					t.Helper()
					if params.SecretId == nil {
						t.Fatal("expect secret id to not be nil")
					}
					secretString := ""

					if *params.SecretId == "alpha" {
						secretString = "charlie"
					}
					return &secretsmanager.GetSecretValueOutput{
						SecretString: &secretString,
					}, nil
				})
			},
			useAltDelims: false,
			data: []byte(`
textTest:
  alpha: {{ (awsText "alpha") | squote }}
`),
			expect: []byte(`
textTest:
  alpha: 'charlie'
`),
		},
		{
			client: func(t *testing.T) SecretsManagerGetSecretAPI {
				return mockGetSecretValueAPI(func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(options *secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
					t.Helper()
					if params.SecretId == nil {
						t.Fatal("expect secret id to not be nil")
					}
					secretString := ""

					if *params.SecretId == "alpha" {
						secretString = "charlie"
					}
					return &secretsmanager.GetSecretValueOutput{
						SecretString: &secretString,
					}, nil
				})
			},
			useAltDelims: true,
			data: []byte(`
textTestAlt:
  alpha: {{<< (awsText "alpha") | squote >>}}
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
				"awsText": client.GetTextSecret,
			}

			result, err := common.ParseSecretsTemplate(tt.data, funcMap)
			if e, a := tt.expect, result; bytes.Compare(e, a) != 0 {
				t.Errorf("expect %v, got %v", string(e), string(a))
			}
		})
	}
}

func TestSecretsClient_GetJsonSecret(t *testing.T) {
	cases := []struct {
		client       func(t *testing.T) SecretsManagerGetSecretAPI
		useAltDelims bool
		expect       []byte
		data         []byte
	}{
		{
			client: func(t *testing.T) SecretsManagerGetSecretAPI {
				return mockGetSecretValueAPI(func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(options *secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
					t.Helper()
					if params.SecretId == nil {
						t.Fatal("expect secret id to not be nil")
					}
					secretString := ""

					if *params.SecretId == "alpha" {
						secretString = `{"bravo":"foo", "charlie":"bar"}`
					}
					return &secretsmanager.GetSecretValueOutput{
						SecretString: &secretString,
					}, nil
				})
			},
			useAltDelims: false,
			data: []byte(`
jsonTest:
  bravo: {{ (aws "alpha" "bravo") | squote }}
  charlie: {{ (awsJson "alpha" "charlie") | quote }}
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
				"aws":     client.GetJSONSecret,
				"awsJson": client.GetJSONSecret,
			}

			result, err := common.ParseSecretsTemplate(tt.data, funcMap)
			if e, a := tt.expect, result; bytes.Compare(e, a) != 0 {
				t.Errorf("expect %v, got %v", string(e), string(a))
			}
		})
	}
}
