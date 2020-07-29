package jws

import (
  "encoding/base64"
  "github.com/slavamuravey/jose/jws/signature"
  "unicode/utf8"
)

type Builder struct {
  payload string
  encodedPayload string
  isPayloadDetached bool
  signatures []signature.Signature
}

func NewBuilder() *Builder {
  return &Builder{}
}

func (b *Builder) WithPayload(payload string) *Builder {
  b.payload = payload

  return b
}

func (b *Builder) WithEncodedPayload(encPayload string) *Builder {
  b.encodedPayload = encPayload

  return b
}

func (b *Builder) WithIsPayloadDetached(isPayloadDetached bool) *Builder {
  b.isPayloadDetached = isPayloadDetached

  return b
}

func (b *Builder) AddSignature(s *signature.Signature) *Builder {
  bClone := b.clone()
  bClone.signatures = append(bClone.signatures, *s)

  return bClone
}

func (b *Builder) clone() *Builder {
  bClone := *b
  bClone.signatures = append(make([]signature.Signature, 0, len(b.signatures)), b.signatures...)

  return &bClone
}

func (b *Builder) Build() *Jws {
  if b.payload == "" {
    panic("the payload is not set")
  }

  if !utf8.Valid([]byte(b.payload)) {
    panic("the payload must be encoded in UTF-8")
  }

  if len(b.signatures) == 0 {
    panic("at least one signature must be set")
  }

  jws := &Jws{payload: b.payload, encodedPayload: b.EncodedPayload(), isPayloadDetached: b.isPayloadDetached}
  jws.signatures = b.signatures

  return jws
}

func (b *Builder) EncodedPayload() string {
  if b.encodedPayload != "" {
    return b.encodedPayload
  }

  var isPayloadEncoded bool

  for _, sign := range b.signatures {
    isPayloadEncoded = signature.IsPayloadEncoded(sign.ProtectedHeader())
    if !(signature.IsPayloadEncoded(b.signatures[0].ProtectedHeader()) == isPayloadEncoded) {
      panic("foreign payload encoding detected")
    }
  }

  if !isPayloadEncoded {
    return b.payload
  }

  return base64.RawURLEncoding.EncodeToString([]byte(b.payload))
}
