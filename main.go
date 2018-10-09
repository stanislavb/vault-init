// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"crypto/tls"
	"github.com/hashicorp/vault/api"
	"github.com/kelseyhightower/vault-init/pkg/keystore"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

var (
	checkInterval string
)

const (
	providerGcp = "gcp"
	providerAws = "aws"
)

func createGcpKeystore() *keystore.GcpKeystore {
	gcsBucketName := os.Getenv("GCS_BUCKET_NAME")
	if gcsBucketName == "" {
		log.Fatal("GCS_BUCKET_NAME must be set and not empty")
	}

	kmsKeyID := os.Getenv("KMS_KEY_ID")
	if kmsKeyID == "" {
		log.Fatal("KMS_KEY_ID must be set and not empty")
	}

	gcpKeystore, err := keystore.NewGcpKeystore(gcsBucketName, kmsKeyID)
	if err != nil {
		log.Fatalln(err)
	}

	return gcpKeystore
}

func createAwsKeystore() *keystore.AwsKeystore {
	kmsKeyID := os.Getenv("KMS_KEY_ID")
	if kmsKeyID == "" {
		log.Fatal("KMS_KEY_ID must be set and not empty")
	}

	secretsPath := os.Getenv("AWS_SECRETS_PATH")
	if secretsPath == "" {
		log.Fatal("AWS_SECRETS_PATH must be set and not empty")
	}

	return keystore.NewAwsKeystore(kmsKeyID, secretsPath)
}

func createKeystore() keystore.Keystore {
	cloudProvider := os.Getenv("CLOUD_PROVIDER")
	if cloudProvider == "" {
		cloudProvider = providerGcp
	}

	switch cloudProvider {
	case providerGcp:
		return createGcpKeystore()
	case providerAws:
		return createAwsKeystore()
	}

	log.Fatalf("Unknow CLOUD_PROVIDER: %s", cloudProvider)
	return nil
}

func main() {
	log.Println("Starting the vault-init service...")

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
	}

	checkInterval = os.Getenv("CHECK_INTERVAL")
	if checkInterval == "" {
		checkInterval = "10"
	}

	i, err := strconv.Atoi(checkInterval)
	if err != nil {
		log.Fatalf("CHECK_INTERVAL is invalid: %s", err)
	}

	checkIntervalDuration := time.Duration(i) * time.Second

	keystoreClient := createKeystore()
	defer keystoreClient.Close()

	httpClient := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = vaultAddr
	vaultConfig.HttpClient = &httpClient
	vaultClient, err := api.NewClient(vaultConfig)
	if err != nil {
		log.Fatalf("Failed to create vault client %s", err)
	}

	signalCh := make(chan os.Signal)
	signal.Notify(signalCh,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGKILL,
	)

	stop := func() {
		log.Printf("Shutting down")
		keystoreClient.Close()
		os.Exit(0)
	}

	for {
		select {
		case <-signalCh:
			stop()
		case <-time.After(checkIntervalDuration):
		}
		response, err := vaultClient.Sys().Health()

		if err != nil {
			log.Println(err)
			time.Sleep(checkIntervalDuration)
			continue
		}

		if !response.Initialized {
			log.Println("Vault is not initialized. Initializing and unsealing...")
			initialize(vaultClient, keystoreClient)
			unseal(vaultClient, keystoreClient)
			continue
		}
		if response.Sealed {
			log.Println("Vault is sealed. Unsealing...")
			unseal(vaultClient, keystoreClient)
			continue
		}
		if response.Standby {
			log.Println("Vault is unsealed and in standby mode.")
			continue
		}
	}
}

func initialize(vaultClient *api.Client, keystoreClient keystore.Keystore) {
	initRequest := api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}

	initResponse, err := vaultClient.Sys().Init(&initRequest)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Encrypting unseal keys and the root token...")

	err = keystoreClient.EncryptAndWrite(initResponse)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Initialization complete.")
}

func unseal(vaultClient *api.Client, keystoreClient keystore.Keystore) {
	initResponse, err := keystoreClient.ReadAndDecrypt()
	if err != nil {
		log.Println(err)
		return
	}

	for _, key := range initResponse.KeysB64 {
		done, err := unsealOne(vaultClient, key)
		if done {
			return
		}

		if err != nil {
			log.Println(err)
			return
		}
	}
}

func unsealOne(vaultClient *api.Client, key string) (bool, error) {
	unsealResponse, err := vaultClient.Sys().Unseal(key)
	if err != nil {
		return false, err
	}

	if !unsealResponse.Sealed {
		return true, nil
	}

	return false, nil
}
