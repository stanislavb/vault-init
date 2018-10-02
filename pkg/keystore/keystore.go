package keystore

import (
	"fmt"
	"github.com/kelseyhightower/vault-init/pkg/vault"
	"runtime"
)

var (
	UserAgent = fmt.Sprintf("vault-init/0.1.0 (%s)", runtime.Version())
)

type Keystore interface {
	Close()
	EncryptAndWrite(vault.InitResponse) error
	ReadAndDecrypt() (*vault.InitResponse, error)
}
