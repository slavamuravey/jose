package jwk

import (
  "fmt"
  "github.com/slavamuravey/jose/internal/utils"
)

type Jwk interface {
  Kty() string
  Use() string
  KeyOps() []string
  Alg() string
  Kid() string
  X5u() string
  X5c() string
  X5t() string
  X5tS256() string
}

func CheckKeyUsage(key Jwk, usage string) {
  if key.Use() != "" {
    checkUsage(key, usage)
  }
  if len(key.KeyOps()) > 0 {
    checkOperation(key, usage)
  }
}

func CheckKeyAlgorithm(key Jwk, algorithm string) {
  if key.Alg() == "" {
    return
  }

  if key.Alg() != algorithm {
    panic(fmt.Sprintf(`key is only allowed for algorithm "%s"`, key.Alg()))
  }
}

func checkUsage(key Jwk, usage string) {
  use := key.Use()

  switch usage {
  case "verification":
    fallthrough
  case "signature":
    if use != "sig" {
      panic("key cannot be used to sign or verify a signature")
    }
  case "encryption":
    fallthrough
  case "decryption":
    if use != "enc" {
      panic("key cannot be used to encrypt or decrypt")
    }
  default:
    panic("unsupported key usage")
  }
}

func checkOperation(key Jwk, usage string) {
  ops := key.KeyOps()
  switch usage {
  case "verification":
    if !utils.Contains("verify", ops) {
      panic("key cannot be used to verify a signature")
    }
  case "signature":
    if !utils.Contains("sign", ops) {
      panic("key cannot be used to sign")
    }
  case "encryption":
    if !utils.Contains("encrypt", ops) && !utils.Contains("wrapKey", ops) && !utils.Contains("deriveKey", ops) {
      panic("key cannot be used to encrypt")
    }
  case "decryption":
    if !utils.Contains("decrypt", ops) && !utils.Contains("unwrapKey", ops) && !utils.Contains("deriveBits", ops) {
      panic("key cannot be used to decrypt")
    }
  default:
    panic("unsupported key usage")
  }
}
