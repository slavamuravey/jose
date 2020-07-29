package jwk

type Jwk interface {
  Kty() string
  Use() string
  KeyOps() string
  Alg() string
  Kid() string
  X5u() string
  X5c() string
  X5t() string
  X5tS256() string
}