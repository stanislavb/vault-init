package keystore

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"runtime"
)

var (
	UserAgent = fmt.Sprintf("vault-init/0.1.0 (%s)", runtime.Version())
)

type Keystore interface {
	Close()
	EncryptAndWrite(*api.InitResponse) error
	ReadAndDecrypt() (*api.InitResponse, error)
}
