package serializer

import (
  "encoding/base64"
  "encoding/json"
  "github.com/slavamuravey/jose/jws"
  "github.com/slavamuravey/jose/jws/signature"
)

type JsonFlattened struct {
}

func NewJsonFlattened() *JsonFlattened {
  return &JsonFlattened{}
}

func (s *JsonFlattened) Serialize(jws *jws.Jws, index int) (string, error) {
  sign := jws.Signature(index)

  encodedPayload := jws.EncodedPayload()
  encodedProtectedHeader := sign.EncodedProtectedHeader()
  header := sign.Header()

  data := make(map[string]interface{})

  if encodedPayload != "" {
    data["payload"] = encodedPayload
  }
  if encodedProtectedHeader != "" {
    data["protected"] = encodedProtectedHeader
  }
  if 0 != len(header) {
    data["header"] = header
  }
  data["signature"] = base64.RawURLEncoding.EncodeToString(sign.Signature())

  bytes, _ := json.Marshal(data)

  return string(bytes), nil
}

func (s *JsonFlattened) Unserialize(input string) *jws.Jws {
  data := make(map[string]interface{})
  json.Unmarshal([]byte(input), &data)

  encodedSignature, ok := data["signature"]

  if !ok {
    panic("unsupported input")
  }

  sign, _ := base64.RawURLEncoding.DecodeString(encodedSignature.(string))

  encodedProtectedHeader, ok := data["protected"]

  var protectedHeader signature.ProtectedHeader

  if ok {
    decodedProtectedHeader, _ := base64.RawURLEncoding.DecodeString(encodedProtectedHeader.(string))
    json.Unmarshal(decodedProtectedHeader, &protectedHeader)
  }

  header, ok := data["header"]
  if !ok {
    header = signature.Header(nil)
  }

  encodedPayload, ok := data["payload"]
  var payload string

  if ok {
    if signature.IsPayloadEncoded(protectedHeader) {
      bytes, _ := base64.RawURLEncoding.DecodeString(encodedPayload.(string))
      payload = string(bytes)
    } else {
      payload = encodedPayload.(string)
    }
  }

  return jws.NewBuilder().
    WithPayload(payload).
    WithEncodedPayload(encodedPayload.(string)).
    WithIsPayloadDetached(encodedPayload.(string) == "").
    AddSignature(
      signature.NewBuilder().
        WithSignature(sign).
        WithProtectedHeader(protectedHeader).
        WithEncodedProtectedHeader(encodedProtectedHeader.(string)).
        WithHeader(header.(signature.Header)).
        Build(),
    ).
    Build()
}