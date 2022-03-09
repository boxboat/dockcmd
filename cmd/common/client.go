package common

type SecretClient interface {
	GetJSONSecret(secretName string, secretKey string) (string, error)
	GetTextSecret(secretName string) (string, error)
}
