package keystore

import (
	"fmt"
	"runtime"

	"github.com/hashicorp/vault/api"
)

var (
	UserAgent      = fmt.Sprintf("vault-init/0.2.0 (%s)", runtime.Version())
	unsealKeysFile = "vault/unseal-keys.json"
	rootTokenFile  = "vault/root-token"
)

type Keystore interface {
	Close()
	EncryptAndWrite(*api.InitResponse) error
	ReadAndDecrypt() (*api.InitResponse, error)
}
