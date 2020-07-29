package jws

import "github.com/slavamuravey/jose/jws/signature"

type Jws struct {
  payload string
  encodedPayload string
  isPayloadDetached bool
  signatures []signature.Signature
}

func (jws *Jws) Payload() string {
  return jws.payload
}

func (jws *Jws) EncodedPayload() string {
  if jws.IsPayloadDetached() {
    return ""
  }

  return jws.encodedPayload
}

func (jws *Jws) IsPayloadDetached() bool {
  return jws.isPayloadDetached
}

func (jws *Jws) Signatures() []signature.Signature {
  return append(make([]signature.Signature, 0, len(jws.signatures)), jws.signatures...)
}

func (jws *Jws) Signature(id int) signature.Signature {
  return jws.Signatures()[id]
}
