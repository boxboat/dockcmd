// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// copied from https://github.com/hashicorp/vault/blob/main/command/kv_helpers.go
package vault

import (
	"errors"
	"fmt"
	paths "path"
	"strings"

	"github.com/hashicorp/vault/api"
)

// copied from github.com/hashicorp/vault/blob/main/command/kv_helpers.go
func addPrefixToKVPath(path, mountPath, apiPrefix string, skipIfExists bool) string {
	if path == mountPath || path == strings.TrimSuffix(mountPath, "/") {
		return paths.Join(mountPath, apiPrefix)
	}

	pathSuffix := strings.TrimPrefix(path, mountPath)
	for {
		// If the entire mountPath is included in the path, we are done
		if pathSuffix != path {
			break
		}
		// Trim the parts of the mountPath that are not included in the
		// path, for example, in cases where the mountPath contains
		// namespaces which are not included in the path.
		partialMountPath := strings.SplitN(mountPath, "/", 2)
		if len(partialMountPath) <= 1 || partialMountPath[1] == "" {
			break
		}
		mountPath = strings.TrimSuffix(partialMountPath[1], "/")
		pathSuffix = strings.TrimPrefix(pathSuffix, mountPath)
	}

	if skipIfExists {
		if strings.HasPrefix(pathSuffix, apiPrefix) || strings.HasPrefix(pathSuffix, "/"+apiPrefix) {
			return paths.Join(mountPath, pathSuffix)
		}
	}

	return paths.Join(mountPath, apiPrefix, pathSuffix)
}

// copied from github.com/hashicorp/vault/blob/main/command/kv_helpers.go
func isKVv2(path string, client *api.Client) (string, bool, error) {
	mountPath, version, err := kvPreflightVersionRequest(client, path)
	if err != nil {
		return "", false, err
	}

	return mountPath, version == 2, nil
}

// copied from github.com/hashicorp/vault/blob/main/command/kv_helpers.go
func kvPreflightVersionRequest(client *api.Client, path string) (string, int, error) {
	// We don't want to use a wrapping call here so save any custom value and
	// restore after
	currentWrappingLookupFunc := client.CurrentWrappingLookupFunc()
	client.SetWrappingLookupFunc(nil)
	defer client.SetWrappingLookupFunc(currentWrappingLookupFunc)
	currentOutputCurlString := client.OutputCurlString()
	client.SetOutputCurlString(false)
	defer client.SetOutputCurlString(currentOutputCurlString)
	currentOutputPolicy := client.OutputPolicy()
	client.SetOutputPolicy(false)
	defer client.SetOutputPolicy(currentOutputPolicy)

	r := client.NewRequest("GET", "/v1/sys/internal/ui/mounts/"+path)
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// If we get a 404 we are using an older version of vault, default to
		// version 1
		if resp != nil {
			if resp.StatusCode == 404 {
				return "", 1, nil
			}

			// if the original request had the -output-curl-string or -output-policy flag,
			if (currentOutputCurlString || currentOutputPolicy) && resp.StatusCode == 403 {
				// we provide a more helpful error for the user,
				// who may not understand why the flag isn't working.
				err = fmt.Errorf(
					`This output flag requires the success of a preflight request 
to determine the version of a KV secrets engine. Please 
re-run this command with a token with read access to %s. 
Note that if the path you are trying to reach is a KV v2 path, your token's policy must 
allow read access to that path in the format 'mount-path/data/foo', not just 'mount-path/foo'.`, path)
			}
		}

		return "", 0, err
	}

	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", 0, err
	}
	if secret == nil {
		return "", 0, errors.New("nil response from pre-flight request")
	}
	var mountPath string
	if mountPathRaw, ok := secret.Data["path"]; ok {
		mountPath = mountPathRaw.(string)
	}
	options := secret.Data["options"]
	if options == nil {
		return mountPath, 1, nil
	}
	versionRaw := options.(map[string]interface{})["version"]
	if versionRaw == nil {
		return mountPath, 1, nil
	}
	version := versionRaw.(string)
	switch version {
	case "", "1":
		return mountPath, 1, nil
	case "2":
		return mountPath, 2, nil
	}

	return mountPath, 1, nil
}
