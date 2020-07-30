package hmac

import (
  "crypto/hmac"
  "crypto/sha512"
  "github.com/slavamuravey/jose/jwk"
)

type HS384 struct {
}

func (a *HS384) Hash(key jwk.OctKey, input string) []byte {
  k := []byte(key.K())
  h := hmac.New(sha512.New384, k)
  h.Write([]byte(input))

  return h.Sum(nil)
}

func (a *HS384) Verify(key jwk.OctKey, value string, hash []byte) bool {
  return string(hash) == string(a.Hash(key, value))
}
