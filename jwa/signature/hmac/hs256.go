package hmac

import (
  "crypto/hmac"
  "crypto/sha256"
  "github.com/slavamuravey/jose/jwk"
)

type HS256 struct {
}

func (a *HS256) Hash(key jwk.OctKey, input string) []byte {
  k := []byte(key.K())
  h := hmac.New(sha256.New, k)
  h.Write([]byte(input))

  return h.Sum(nil)
}

func (a *HS256) Verify(key jwk.OctKey, value string, hash []byte) bool {
  return string(hash) == string(a.Hash(key, value))
}
