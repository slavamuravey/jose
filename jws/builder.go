package jws

import (
  "encoding/base64"
  "encoding/json"
  "github.com/slavamuravey/jose/jws/signature"
  "unicode/utf8"
)

type Builder struct {
  payload string
  encodedPayload string
  isPayloadDetached bool
  signatureInputParams []signature.InputParams
}

func NewBuilder() *Builder {
  return &Builder{}
}

func (b *Builder) WithPayload(payload string) *Builder {
  b.payload = payload

  return b
}

func (b *Builder) WithEncodedPayload(encodedPayload string) *Builder {
  b.encodedPayload = encodedPayload

  return b
}

func (b *Builder) WithIsPayloadDetached(isPayloadDetached bool) *Builder {
  b.isPayloadDetached = isPayloadDetached

  return b
}

func (b *Builder) AddSignatureInputParams(params *signature.InputParams) *Builder {

  bClone := b.clone()
  bClone.signatureInputParams = append(bClone.signatureInputParams, *params)

  return bClone
}

func (b *Builder) clone() *Builder {
  bClone := *b
  bClone.signatureInputParams = append(make([]signature.InputParams, 0, len(b.signatureInputParams)), b.signatureInputParams...)

  return &bClone
}

func (b *Builder) Build() *Jws {
  if b.payload == "" {
    panic("the payload is not set")
  }

  if !utf8.Valid([]byte(b.payload)) {
    panic("the payload must be encoded in UTF-8")
  }

  if len(b.signatureInputParams) == 0 {
    panic("at least one signature must be set")
  }

  jws := &Jws{payload: b.payload, encodedPayload: b.EncodedPayload(), isPayloadDetached: b.isPayloadDetached}

  for _, params := range b.signatureInputParams {
    signature := signature.NewBuilder().
      WithKey(params.Key()).
      WithSignature(params.Signature()).
      WithEncodedPayload(b.EncodedPayload()).
      WithProtectedHeader(params.ProtectedHeader()).
      WithEncodedProtectedHeader(b.EncodedProtectedHeader(&params)).
      WithHeader(params.Header()).
      Build()
    jws.signatures = append(jws.signatures, *signature)
  }

  return jws
}

func (b *Builder) EncodedPayload() string {
  if b.encodedPayload != "" {
    return b.encodedPayload
  }

  var isPayloadEncoded bool

  for _, sign := range b.signatureInputParams {
    isPayloadEncoded = signature.IsPayloadEncoded(sign.ProtectedHeader())
    if !(signature.IsPayloadEncoded(b.signatureInputParams[0].ProtectedHeader()) == isPayloadEncoded) {
      panic("foreign payload encoding detected")
    }
  }

  if !isPayloadEncoded {
    return b.payload
  }

  return base64.RawURLEncoding.EncodeToString([]byte(b.payload))
}

func (b *Builder) EncodedProtectedHeader(params *signature.InputParams) string {
  if params.EncodedProtectedHeader() != "" {
    return params.EncodedProtectedHeader()
  }

  if len(params.ProtectedHeader()) > 0 {
    bytes, _ := json.Marshal(params.ProtectedHeader())
    return base64.RawURLEncoding.EncodeToString(bytes)
  }

  return ""
}
