package serializer

import (
  "encoding/base64"
  "encoding/json"
  "errors"
  "fmt"
  "github.com/slavamuravey/jose/jws"
  "github.com/slavamuravey/jose/jws/signature"
  "regexp"
  "strings"
)

type Compact struct {
}

func NewCompact() *Compact {
  return &Compact{}
}

func (s *Compact) Serialize(jws *jws.Jws, index int) (string, error) {
  sign := jws.Signature(index)

  if 0 != len(sign.Header()) {
    return "", errors.New("the signature contains unprotected header parameters and cannot be converted into compact JSON")
  }

  if !signature.IsPayloadEncoded(sign.ProtectedHeader()) && jws.EncodedPayload() != "" {
    r, _ := regexp.Compile(`^[\x{20}-\x{2d}|\x{2f}-\x{7e}]*$`)
    if !r.MatchString(jws.Payload()) {
      return "", errors.New("unable to convert the JWS with non-encoded payload")
    }
  }

  return fmt.Sprintf(
    "%s.%s.%s",
    sign.EncodedProtectedHeader(),
    jws.EncodedPayload(),
    base64.RawURLEncoding.EncodeToString(sign.Signature()),
  ), nil
}

func (s *Compact) Unserialize(input string) *jws.Jws {
  parts := strings.Split(input, ".")

  if 3 != len(parts) {
    panic("unsupported input")
  }

  encodedProtectedHeader := parts[0]
  encodedPayload := parts[1]
  encodedSignature := parts[2]
  var payload []byte
  var protectedHeader signature.ProtectedHeader

  decodedHeader, _ := base64.RawURLEncoding.DecodeString(encodedProtectedHeader)
  json.Unmarshal(decodedHeader, &protectedHeader)

  hasPayload := "" != encodedPayload

  if hasPayload {
    if signature.IsPayloadEncoded(protectedHeader) {
      payload, _ = base64.RawURLEncoding.DecodeString(encodedPayload)
    } else {
      payload = []byte(encodedPayload)
    }
  }

  sign, _ := base64.RawURLEncoding.DecodeString(encodedSignature)

  return jws.NewBuilder().
    WithPayload(string(payload)).
    WithEncodedPayload(encodedPayload).
    WithIsPayloadDetached(!hasPayload).
    AddSignature(
      signature.NewBuilder().
        WithSignature(sign).
        WithProtectedHeader(protectedHeader).
        WithEncodedProtectedHeader(encodedProtectedHeader).
        Build(),
    ).
    Build()
}
