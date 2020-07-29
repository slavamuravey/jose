package signature

import (
  "errors"
  "fmt"
  "github.com/slavamuravey/jose/internal/utils"
  "github.com/slavamuravey/jose/jwa"
  "github.com/slavamuravey/jose/jwk"
)

type Builder struct {
  signature []byte
  key jwk.Jwk
  encodedPayload string
  protectedHeader ProtectedHeader
  encodedProtectedHeader string
  header Header
}

func NewBuilder() *Builder {
  return &Builder{}
}

func (b *Builder) WithSignature(signature []byte) *Builder {
  b.signature = signature

  return b
}

func (b *Builder) WithKey(key jwk.Jwk) *Builder {
  b.key = key

  return b
}

func (b *Builder) WithEncodedPayload(encodedPayload string) *Builder {
  b.encodedPayload = encodedPayload

  return b
}

func (b *Builder) WithProtectedHeader(protectedHeader ProtectedHeader) *Builder {
  b.protectedHeader = protectedHeader

  return b
}

func (b *Builder) WithEncodedProtectedHeader(encodedProtectedHeader string) *Builder {
  b.encodedProtectedHeader = encodedProtectedHeader

  return b
}

func (b *Builder) WithHeader(header Header) *Builder {
  b.header = header

  return b
}

func (b *Builder) Build() *Signature {
  b.checkB64AndCriticalHeader()

  signature, err := b.Signature()

  if err != nil {
    panic(err.Error())
  }

  s := &Signature{encodedProtectedHeader: b.encodedProtectedHeader, signature: signature, header: b.header}

  if b.encodedProtectedHeader == "" {
    s.protectedHeader = make(ProtectedHeader)
  } else {
    s.protectedHeader = b.protectedHeader
  }

  return s
}

// checkB64AndCriticalHeader panic if the header parameter "crit" is missing, invalid or does not contain "b64" when "b64" is set
func (b *Builder) checkB64AndCriticalHeader() {
  if _, ok := b.protectedHeader["b64"]; !ok {
    return
  }

  crit, ok := b.protectedHeader["crit"]

  if !ok {
    panic(`the protected header parameter "crit" is mandatory when protected header parameter "b64" is set`)
  }

  critSlice, ok := crit.([]string)

  if !ok {
    panic(`the protected header parameter "crit" must be a slice of strings`)
  }

  if !utils.Contains("b64", critSlice) {
    panic(`the protected header parameter "crit" must contain "b64" when protected header parameter "b64" is set`)
  }
}

func (b *Builder) Signature() ([]byte, error) {
  if len(b.signature) > 0 {
    return b.signature, nil
  }

  if b.key == nil {
    return nil, errors.New("key is not set")
  }

  if b.encodedPayload == "" {
    return nil, errors.New("payload is not set")
  }

  return jwa.Sign(b.key.(jwk.Oct), fmt.Sprintf(
    "%s.%s",
    b.encodedProtectedHeader,
    b.encodedPayload,
  )), nil
}
