package signature

import (
  "fmt"
  "github.com/slavamuravey/jose/jwk"
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

type InputParams struct {
  key                    jwk.Jwk
  signature              []byte
  protectedHeader        ProtectedHeader
  encodedProtectedHeader string
  header                 Header
}

func (p *InputParams) Key() jwk.Jwk {
  return p.key
}

func (p *InputParams) Signature() []byte {
  return p.signature
}

func (p *InputParams) ProtectedHeader() ProtectedHeader {
  return p.protectedHeader
}

func (p *InputParams) EncodedProtectedHeader() string {
  return p.encodedProtectedHeader
}

func (p *InputParams) Header() Header {
  return p.header
}

type InputParamsBuilder struct {
  key                    jwk.Jwk
  signature              []byte
  protectedHeader        ProtectedHeader
  encodedProtectedHeader string
  header                 Header
}

func NewInputParamsBuilder() *InputParamsBuilder {
  return &InputParamsBuilder{}
}

func (b *InputParamsBuilder) WithSignature(signature []byte) *InputParamsBuilder {
  b.signature = signature

  return b
}

func (b *InputParamsBuilder) WithKey(key jwk.Jwk) *InputParamsBuilder {
  b.key = key

  return b
}

func (b *InputParamsBuilder) WithProtectedHeader(protectedHeader ProtectedHeader) *InputParamsBuilder {
  b.protectedHeader = protectedHeader

  return b
}

func (b *InputParamsBuilder) WithEncodedProtectedHeader(encodedProtectedHeader string) *InputParamsBuilder {
  b.encodedProtectedHeader = encodedProtectedHeader

  return b
}

func (b *InputParamsBuilder) WithHeader(header Header) *InputParamsBuilder {
  b.header = header

  return b
}

func (b *InputParamsBuilder) Build() *InputParams {
  return &InputParams{
    key: b.key,
    signature: b.signature,
    protectedHeader: b.protectedHeader,
    encodedProtectedHeader: b.encodedProtectedHeader,
    header: b.header,
  }
}
