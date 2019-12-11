# dockcmd
[![Build Status](https://travis-ci.org/boxboat/dockcmd.svg?branch=master)](https://travis-ci.org/boxboat/dockcmd)

`dockcmd` is a tool providing a collection of [BoxOps](https://boxops.io) utility functions. Which can be used standalone or to accelerate CI/CD with BoxBoat's [dockhand](https://github.com/boxboat/dockhand).


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

Retrieve secrets stored as JSON from AWS Secrets Manager. Input files are defined using go templating and `dockcmd` supports sprig functions, as well as alternate template delimiters `<< >>` using `--use-alt-delims`. External values can be passed in using `--set key=value`

`dockcmd aws get-secrets --region us-east-1 --set TargetEnv=prod --input-file secret-values.yaml`

`secret-values.yaml`:
```
---
foo:
  keyA: {{ (aws (printf "%s-%s" .TargetEnv "foo") "a") | squote }}
  keyB: {{ (aws (printf "%s-%s" .TargetEnv "foo") "b") | squote }}
  charlie:
    keyC: {{ (aws "foo" "c") | squote }}
keyD: {{ (aws "root" "d") | quote }}
```

output:
```
foo:
  keyA: '<value-of-secret/foo-prod-a-from-aws-secrets-manager>'
  keyB: '<value-of-secret/foo-prod-b-from-aws-secrets-manager>'
  charlie:
    keyC: '<value-of-secret/foo-charlie-c-from-aws-secrets-manager>'
keyD: "<value-of-secret/root-d-from-aws-secrets-manager>"
```
***
## `azure`

Azure utilities are under the `azure` sub-command. For authentication, Azure commands make use of these flags and environment variables:

* Client Id/Client Secret
  * Environment: `${AZURE_CLIENT_ID}` `${AZURE_CLIENT_SECRET}`
  * Args: `--client-id <access-key>` `--client-secret <secret-key>`
* Tenant:
  * Environment: `${AZURE_TENANT_ID}`
  * Args: `--tenant <tenant-id>`

See `dockcmd azure --help` for more details on `azure` flags.

### `get-secrets`

Retrieve secrets stored as JSON from AWS Secrets Manager. Input files are defined using go templating and `dockcmd` supports sprig functions, as well as alternate template delimiters `<< >>` using `--use-alt-delims`. External values can be passed in using `--set key=value`

`dockcmd azure get-secrets --set TargetEnv=prod --input-file secret-values.yaml`

`secret-values.yaml`:
```
---
foo:
  keyA: {{ (azureJson "foo" "a") | squote }}
  keyB: {{ (azureJson "foo" "b") | squote }}
  charlie:
    keyC: {{ (azureJson "foo-charlie" "c") | squote }}
keyD: {{ (azureText "root" ) | quote }}
```

output:
```
foo:
  keyA: '<value-of-secret/foo-a-frome-azure-key-vault>'
  keyB: '<value-of-secret/foo-b-frome-azure-key-vault>'
  charlie:
    keyC: '<value-of-secret/foo-charlie-c-frome-azure-key-vault>'
keyD: "<value-of-secret/root-from-azure-key-vault>"
```

***
## `es`
Elasticsearch utilities are under the `es` sub-command. Currently supports Elasticsearch API major version v6 and v7. For authentication, `es` commands will use the environment or credentials passed in as arguments:

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
## `vault`

Vault utilities are under the `vault` sub-command. For authentication, `vault` commands will use the environment or credentials passed in as arguments:

`--vault-token <vault-token>` or `${VAULT_TOKEN}`
or
`--vault-role-id <vault-role-id> --vault-secret-id <vault-secret-id>`

See `dockcmd vault --help` for more details on `vault` flags.

### `get-secrets`

Retrieve secrets from Vault. Input files are defined using go templating and `dockcmd` supports sprig functions, as well as alternate template delimiters `<< >>` using `--use-alt-delims`


`dockcmd vault get-secrets --vault-addr https://vault --set TargetEnv=prod --input-file secret-values.yaml`

`secret-values.yaml`:
```
---
foo:
  keyA: {{ (vault "secret/foo" "a") | squote }}
  keyB: {{ (vault "secret/foo" "b") | squote }}
  charlie:
    keyC: {{ (vault (printf "%s/%s/%s" "secret/foo" .TargetEnv "charlie") "c") | squote }}
keyD: {{ (vault "secret/root" "d") | quote }}
```

output:
```
foo:
  keyA: '<value-of-secret/foo-a-from-vault>'
  keyB: '<value-of-secret/foo-b-from-vault>'
  charlie:
    keyC: '<value-of-secret/foo/prod/charlie-c-from-vault>'
keyD: "<value-of-secret/root-d-from-vault>"
```
