# dockcmd
![Main](https://github.com/boxboat/dockcmd/workflows/Main/badge.svg?branch=master)

`dockcmd` is a tool providing a collection of [BoxOps](https://boxops.io) utility functions. Which can be used standalone or to accelerate CI/CD with BoxBoat's [dockhand](https://github.com/boxboat/dockhand).

[dockhand-secrets-operator](https://github.com/boxboat/dockhand-secrets-operator) leverages this project to facilitate secrets management within Kubernetes. 


***
## `aws`


AWS utilities are under the `aws` sub-command. For authentication, AWS commands make use of the standard AWS credentials providers and will check in order:

* Access Key/Secret key
  * Environment: `${AWS_ACCESS_KEY_ID}` `${AWS_SECRET_ACCESS_KEY}`
  * Args: `--access-key-id <access-key>` `--secret-access-key <secret-key>`
* AWS Profile: `~/.aws/config` and `~/.aws/credentials`
  * Environment: `${AWS_PROFILE}`
  * Args: `--profile <profile-name>`  
* EC2 Instance Profile

See `dockcmd aws --help` for more details on `aws` flags.

### `get-secrets`

Retrieve secrets stored as JSON from AWS Secrets Manager. Input files are defined using go templating and `dockcmd` supports sprig functions, `urlEncode`, `urlDecode`, and the Helm `toYaml` function, as well as alternate template delimiters `<< >>` using `--use-alt-delims`. External values can be passed in using `--set key=value` or with `--values values.yaml`.


Notes:
 - the `aws(secretName,secretKey)` function is now aliased to `awsJson(secretName, secretKey)`. `aws` will not be removed.
 - `secretName` can be the Secret ARN - necessary in the case of across account retrieval 


`dockcmd aws get-secrets --region us-east-1 --set TargetEnv=prod --input-file secret-values.yaml`

`secret-values.yaml`:
```yaml
---
foo:
  keyA: {{ (aws (printf "%s-%s" .TargetEnv "foo") "a") | squote }}
  keyB: {{ (aws (printf "%s-%s" .TargetEnv "foo") "b") | squote }}
  charlie:
    keyC: {{ (aws "foo" "c") | squote }}
keyD: {{ (awsText "root") | quote }}
```

output:
```yaml
foo:
  keyA: '<value-of-secret/foo-prod-a-from-aws-secrets-manager>'
  keyB: '<value-of-secret/foo-prod-b-from-aws-secrets-manager>'
  charlie:
    keyC: '<value-of-secret/foo-charlie-c-from-aws-secrets-manager>'
keyD: "<value-of-secret/root-from-aws-secrets-manager>"
```

Optionally, if you desire to retrieve a specific version of secret from AWS Secrets Manager you can append `?version=UID` or `?version=latest` to the secret name above, for example:
```yaml
---
---
foo:
  keyA: {{ (aws (printf "%s-%s?version="be70653b-f0d8-47ee-8785-8cbb5be463f8" .TargetEnv "foo") "a") | squote }}
  keyB: {{ (aws (printf "%s-%s?version=latest" .TargetEnv "foo") "b") | squote }}
  charlie:
    keyC: {{ (aws "foo" "c") | squote }}
keyD: {{ (awsText "root") | quote }}
```

Note if you need to find the versions UID you can use the AWS CLI `aws secretmanager list-secret-version-ids --secret-id foo`

***
## `azure`

Azure utilities are under the `azure` sub-command. For authentication, Azure commands make use of these flags and environment variables:

* Client Id/Client Secret
  * Environment: `${AZURE_CLIENT_ID}` `${AZURE_CLIENT_SECRET}`
  * Args: `--client-id <access-key>` `--client-secret <secret-key>`
* Tenant:
  * Environment: `${AZURE_TENANT_ID}`
  * Args: `--tenant <tenant-id>`

Alternatively the [azure cli](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest) can be used to authenticate in the current shell with `az login`.

See `dockcmd azure --help` for more details on `azure` flags.

### `get-secrets`

Retrieve secrets stored as JSON from Azure Key Vaults. Input files are defined using go templating and `dockcmd` supports sprig functions, `urlEncode`, `urlDecode`, and the Helm `toYaml` function, as well as alternate template delimiters `<< >>` using `--use-alt-delims`. External values can be passed in using `--set key=value` or with `--values values.yaml`.

Secrets can be stored in Azure Key Vault either as plain text or as a json payload. See example below:

`dockcmd azure get-secrets --set TargetEnv=prod --input-file secret-values.yaml`

`secret-values.yaml`:
```yaml
---
foo:
  keyA: {{ (azureJson "foo" "a") | squote }}
  keyB: {{ (azureJson "foo" "b") | squote }}
  charlie:
    keyC: {{ (azureJson "foo-charlie" "c") | squote }}
keyD: {{ (azureText "root" ) | quote }}
```

output:
```yaml
foo:
  keyA: '<value-of-secret/foo-a-from-azure-key-vault>'
  keyB: '<value-of-secret/foo-b-from-azure-key-vault>'
  charlie:
    keyC: '<value-of-secret/foo-charlie-c-from-azure-key-vault>'
keyD: "<value-of-secret/root-from-azure-key-vault>"
```

Optionally, if you desire to retrieve a specific version of secret from Azure Key Vault you can append `?version=ID` or `?version=latest` to the secret name above, for example:
```yaml
---
foo:
  keyA: {{ (azureJson "foo?version=latest" "a") | squote }}
  keyB: {{ (azureJson "foo?version=d98097e7bbe04f67ba0846b511936d2d" "b") | squote }}
  charlie:
    keyC: {{ (azureJson "foo-charlie" "c") | squote }}
keyD: {{ (azureText "root" ) | quote }}
```

***
***
## `gcp`

GCP utilities are under the `gcp` sub-command. For authentication, GCP commands make use of either [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials), or you can provide a credentials JSON file.

* GCP Credential JSON File
  * Args: `--credentials-file <key.json>`


For local usage you can use the [gcloud cli](https://cloud.google.com/sdk/gcloud/reference/auth/login) can be used to authenticate in the current shell with `gcloud auth application-default login`.

See `dockcmd gcp --help` for more details on `gcp` flags.

### `get-secrets`

Retrieve secrets stored as JSON from GCP Secrets Manager. Input files are defined using go templating and `dockcmd` supports sprig functions, `urlEncode`, `urlDecode`, and the Helm `toYaml` function, as well as alternate template delimiters `<< >>` using `--use-alt-delims`. External values can be passed in using `--set key=value` or with `--values values.yaml`.

Secrets can be stored in GCP Secrets Manager either as plain text or as a json payload. See example below:

`dockcmd gcp get-secrets --project my-project --set TargetEnv=prod --input-file secret-values.yaml`

`secret-values.yaml`:
```yaml
---
foo:
  keyA: {{ (gcpJson "foo" "a") | squote }}
  keyB: {{ (gcpJson "foo" "b") | squote }}
  charlie:
    keyC: {{ (gcpJson "foo-charlie" "c") | squote }}
keyD: {{ (gcpText "root" ) | quote }}
```

output:
```yaml
foo:
  keyA: '<value-of-secret/foo-a-from-gcp-secrets-manager>'
  keyB: '<value-of-secret/foo-b-from-gcp-secrets-manager>'
  charlie:
    keyC: '<value-of-secret/foo-charlie-c-from-gcp-secrets-manager>'
keyD: "<value-of-secret/root-from-gcp-secrets-manager>"
```

Optionally, if you desire to retrieve a specific version of secret from GCP Secrets manager you can append `?version=X` or `?version=latest` to the secret name above, for example:
```yaml
---
foo:
  keyA: {{ (gcpJson "foo?version=1" "a") | squote }}
  keyB: {{ (gcpJson "foo?version=latest" "b") | squote }}
  charlie:
    keyC: {{ (gcpJson "foo-charlie?version=2" "c") | squote }}
keyD: {{ (gcpText "root" ) | quote }}
```

***

## `es`
Elasticsearch utilities are under the `es` sub-command. Currently, supports Elasticsearch API major version v6 and v7. For authentication, `es` commands will use the environment or credentials passed in as arguments:

#### Basic Auth
`--username <username>` or `${ES_USERNAME}`
`--password <password>` or `${ES_PASSWORD}`

#### API Key
Note, if you set the `api-key` then it will override any Basic Auth parameters provided:
`--api-key <base64-encoded-auth-token>` or `${ES_API_KEY}`

#### No Auth
If authorization is not required, simply omit the above flags.

See `dockcmd es --help` for more details on `es` flags.

### `get-indices`
Retrieve indices from ES, output is json payload.

See `dockcmd es get-indices --help` for more details.

### `delete-indices`
Delete indices from ES.

See `dockcmd es delete-indices --help` for more details

***

## `gotpl`
`dockcmd gotpl` mirrors the capabilities in each of the `get-secrets` commands but does not connect to a secrets backend. Essentially this command is a go template processor that supports sprig functions, `urlEncode`, `urlDecode`, and the Helm `toYaml` function with `helm` like value passing.

Input files are defined using go templating and `dockcmd` supports sprig functions, `urlEncode`, `urlDecode`, and the Helm `toYaml` function, as well as alternate template delimiters `<< >>` using `--use-alt-delims`. External values can be passed in using `--set key=value` or with `--values values.yaml`.

***

## `vault`

Vault utilities are under the `vault` sub-command. For authentication, `vault` commands will use the environment or credentials passed in as arguments:

`--vault-token <vault-token>` or `${VAULT_TOKEN}`
or
`--vault-role-id <vault-role-id> --vault-secret-id <vault-secret-id>`

See `dockcmd vault --help` for more details on `vault` flags.

### `get-secrets`

Retrieve secrets from Vault `v1` or `v2` KV Secrets Engines. Input files are defined using go templating and `dockcmd` supports sprig functions, `urlEncode`, `urlDecode`, and the Helm `toYaml` function, as well as alternate template delimiters `<< >>` using `--use-alt-delims`. External values can be passed in using `--set key=value` or with `--values values.yaml`.

`dockcmd vault get-secrets --vault-addr https://vault --set TargetEnv=prod --input-file secret-values.yaml`

`secret-values.yaml`:
```yaml
---
foo:
  keyA: {{ (vault "secret/foo" "a") | squote }}
  keyB: {{ (vault "secret/foo" "b") | squote }}
  charlie:
    keyC: {{ (vault (printf "%s/%s/%s" "secret/foo" .TargetEnv "charlie") "c") | squote }}
keyD: {{ (vault "secret/root" "d") | quote }}
```

output:
```yaml
foo:
  keyA: '<value-of-secret/foo-a-from-vault>'
  keyB: '<value-of-secret/foo-b-from-vault>'
  charlie:
    keyC: '<value-of-secret/foo/prod/charlie-c-from-vault>'
keyD: "<value-of-secret/root-d-from-vault>"
```

Optionally, if you desire to retrieve a specific version of secret from Vault V2 Secret Store you can append `?version=X` or `?version=latest` to the secret name above, for example:
```yaml
---
foo:
  keyA: {{ (vault "foo?version=1" "a") | squote }}
  keyB: {{ (vault "foo?version=latest" "b") | squote }}
  charlie:
    keyC: {{ (vault (printf "%s/%s/%s" "secret/foo" .TargetEnv "charlie") "c") | squote }}
keyD: {{ (vault "secret/root" "d") | quote }}
```
