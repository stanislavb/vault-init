package keystore

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/vault/api"
	"log"
)

var (
	unsealKeysFile = "vault/unseal-keys.json"
	rootTokenFile  = "vault/root-token"
)

type AwsKeystore struct {
	kmsKeyID          string
	secretsMgrService *secretsmanager.SecretsManager
}

func NewAwsKeystore(kmsKeyID string) *AwsKeystore {
	secretsMgrService := secretsmanager.New(session.Must(session.NewSession()))

	return &AwsKeystore{
		kmsKeyID:          kmsKeyID,
		secretsMgrService: secretsMgrService,
	}
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
	secretValueInput := secretsmanager.GetSecretValueInput{
		SecretId: &unsealKeysFile,
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
	secretInput := secretsmanager.CreateSecretInput{
		KmsKeyId:     &keystore.kmsKeyID,
		Name:         &name,
		SecretBinary: content,
	}

	_, err := keystore.secretsMgrService.CreateSecretWithContext(context.Background(), &secretInput)
	if err != nil {
		return err
	}

	log.Printf("Secret written to secretsmanager as '%s'", name)
	return nil
}
