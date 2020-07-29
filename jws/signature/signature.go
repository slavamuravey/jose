package signature

import (
  "fmt"
)

type ProtectedHeader map[string]interface{}
type Header map[string]string

type Signature struct {
  encodedProtectedHeader string
  protectedHeader        ProtectedHeader
  header                 Header
  signature              []byte
}

func (s *Signature) ProtectedHeader() ProtectedHeader {
  return s.protectedHeader
}

func (s *Signature) Header() Header {
  return s.header
}

func (s *Signature) EncodedProtectedHeader() string {
  return s.encodedProtectedHeader
}

func (s *Signature) Signature() []byte {
  return s.signature
}

func (s *Signature) HasProtectedHeaderParameter(key string) bool {
  _, ok := s.protectedHeader[key]

  return ok
}

func (s *Signature) ProtectedHeaderParameter(key string) (interface{}, error) {
  if s.HasProtectedHeaderParameter(key) {
    return s.ProtectedHeader()[key], nil
  }

  return "", fmt.Errorf(`the protected header "%s" does not exist`, key)
}

func (s *Signature) HasHeaderParameter(key string) bool {
  _, ok := s.header[key]

  return ok
}

func (s *Signature) HeaderParameter(key string) (string, error) {
  if s.HasHeaderParameter(key) {
    return s.Header()[key], nil
  }

  return "", fmt.Errorf(`the header "%s" does not exist`, key)
}

func IsPayloadEncoded(protectedHeader ProtectedHeader) bool {
  v, hasB64 := protectedHeader["b64"]
  v, isBool := v.(bool)

  return !hasB64 || isBool && true == v.(bool)
}
