package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/profiles/2019-03-01/keyvault/keyvault"
	kvauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/boxboat/dockcmd/cmd/common"
)

var (
	initialized    = false
	TenantID       string
	ClientID       string
	ClientSecret   string
	KeyVaultName   string
	KeyVaultClient keyvault.BaseClient
	SecretCache    map[string]map[string]interface{}
	UseAzCliLogin  = false
)

func getKeyVaultClient() keyvault.BaseClient {
	if !initialized {
		if UseAzCliLogin {
			authorizer, err := kvauth.NewAuthorizerFromCLI()
			common.HandleError(err)
			KeyVaultClient = keyvault.New()
			KeyVaultClient.Authorizer = authorizer
			initialized = true
		} else {
			authorizer, err := kvauth.NewAuthorizerFromEnvironment()
			common.HandleError(err)
			KeyVaultClient = keyvault.New()
			KeyVaultClient.Authorizer = authorizer
			initialized = true
		}
	}
	return KeyVaultClient
}

func GetAzureJSONSecret(secretName string, secretKey string) string {
	common.Logger.Debugf("Retrieving [%s][%s]", secretName, secretKey)

	if val, ok := SecretCache[secretName]; ok {
		common.Logger.Debugf("Using cached [%s][%s]", secretName, secretKey)
		secretStr, ok := val[secretKey].(string)
		if !ok {
			common.HandleError(
				fmt.Errorf(
					"Could not convert [%s][%s] to string",
					secretName,
					secretKey))
		}
		return secretStr
	}

	secretResp, err := getKeyVaultClient().GetSecret(
		context.Background(),
		"https://"+KeyVaultName+".vault.azure.net",
		secretName, "")
	common.HandleError(err)
	secretJSON := *secretResp.Value
	var response map[string]interface{}
	json.Unmarshal([]byte(secretJSON), &response)

	secretStr, ok := response[secretKey].(string)
	if !ok {
		common.HandleError(
			fmt.Errorf(
				"Could not convert Key Vault response[%s][%s] to string",
				secretName,
				secretKey))
	}
	if SecretCache[secretName] == nil {
		SecretCache[secretName] = make(map[string]interface{})
	}
	SecretCache[secretName] = response
	return secretStr
}

func GetAzureTextSecret(secretName string) string {
	common.Logger.Debugf("GetAzureTextSecret [%s]", secretName)

	secretResp, err := getKeyVaultClient().GetSecret(
		context.Background(),
		"https://"+KeyVaultName+".vault.azure.net",
		secretName, "")
	common.HandleError(err)
	secretStr := *secretResp.Value

	return secretStr

}
