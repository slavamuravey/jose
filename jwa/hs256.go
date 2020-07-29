package jwa

import (
  "crypto/hmac"
  "crypto/sha256"
  "github.com/slavamuravey/jose/jwk"
)

func Sign(key jwk.OctKey, input string) []byte {
  k := []byte(key.K())
  h := hmac.New(sha256.New, k)
  h.Write([]byte(input))

  return h.Sum(nil)
}

func Verify(jwk jwk.OctKey, value string, hash []byte) bool {
  return string(hash) == string(Sign(jwk, value))
}
