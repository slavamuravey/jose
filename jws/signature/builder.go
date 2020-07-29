package signature

import "github.com/slavamuravey/jose/internal/utils"

type Builder struct {
  signature []byte
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
  s := &Signature{encodedProtectedHeader: b.encodedProtectedHeader, signature: b.signature, header: b.header}

  if b.encodedProtectedHeader == "" {
    s.protectedHeader = make(ProtectedHeader)
  } else {
    s.protectedHeader = b.protectedHeader
  }

  b.checkB64AndCriticalHeader()

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
