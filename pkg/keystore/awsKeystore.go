package keystore

import (
	"context"
	"encoding/json"
	"log"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/vault/api"
)

type AwsKeystore struct {
	kmsKeyID          string
	secretsPath       string
	secretsMgrService *secretsmanager.SecretsManager
}

type AwsKeystoreConfig struct {
	AwsConfig   *AwsConfig
	KmsKeyID    string
	SecretsPath string
}

type AwsConfig struct {
	Endpoint string
}

func createAwsSession(config *AwsConfig) *session.Session {
	if config.Endpoint != "" {
		return session.Must(session.NewSession(&aws.Config{
			Endpoint:         &config.Endpoint,
			S3ForcePathStyle: aws.Bool(true),
		}))
	}

	return session.Must(session.NewSession())
}

func NewAwsKeystore(config *AwsKeystoreConfig) *AwsKeystore {
	secretsMgrService := secretsmanager.New(createAwsSession(config.AwsConfig))

	return &AwsKeystore{
		kmsKeyID:          config.KmsKeyID,
		secretsPath:       config.SecretsPath,
		secretsMgrService: secretsMgrService,
	}
}

func (keystore *AwsKeystore) secretPath(name string) string {
	return path.Join(strings.TrimRight(keystore.secretsPath, "/"), name)
}

func (keystore AwsKeystore) Close() {
	// nothing to close
}

func (keystore AwsKeystore) EncryptAndWrite(initResponse *api.InitResponse) error {
	// Save and encrypted the unseal keys
	initResponseData, err := json.Marshal(&initResponse)
	if err != nil {
		return err
	}
	err = keystore.createSecret(unsealKeysFile, initResponseData)
	if err != nil {
		return err
	}

	// Save and encrypted the root token
	rootTokenData, err := json.Marshal(&initResponse.RootToken)
	if err != nil {
		return err
	}
	err = keystore.createSecret(rootTokenFile, rootTokenData)
	if err != nil {
		return err
	}

	return nil
}

func (keystore AwsKeystore) ReadAndDecrypt() (*api.InitResponse, error) {
	secretPath := keystore.secretPath(unsealKeysFile)
	secretValueInput := secretsmanager.GetSecretValueInput{
		SecretId: &secretPath,
	}
	secretValueOutput, err := keystore.secretsMgrService.GetSecretValueWithContext(context.Background(), &secretValueInput)
	if err != nil {
		return nil, err
	}

	var initResponse api.InitResponse

	err = json.Unmarshal(secretValueOutput.SecretBinary, &initResponse)
	if err != nil {
		return nil, err
	}
	return &initResponse, nil
}

func (keystore AwsKeystore) createSecret(name string, content []byte) error {
	secretPath := keystore.secretPath(name)
	secretInput := secretsmanager.CreateSecretInput{
		KmsKeyId:     &keystore.kmsKeyID,
		Name:         &secretPath,
		SecretBinary: content,
	}

	_, err := keystore.secretsMgrService.CreateSecretWithContext(context.Background(), &secretInput)
	if err != nil {
		return err
	}

	log.Printf("Secret written to secretsmanager as '%s'", secretPath)
	return nil
}
