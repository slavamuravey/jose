package serializer

import (
  "github.com/slavamuravey/jose/jws"
)

type Serializer interface {
  Serialize(jws *jws.Jws, index int) (string, error)
  Unserialize(token string) *jws.Jws
}
