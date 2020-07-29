package jwk

type OctKey interface {
  Jwk
  K() string
}

type Oct struct {
  // jwk fields
  kty string
  use string
  keyOps string
  alg string
  kid string
  x5u string
  x5c string
  x5t string
  x5tS256 string
  // oct fields
  k string
}

func (k Oct) Kty() string {
  return k.kty
}

func (k Oct) Use() string {
  return k.use
}

func (k Oct) KeyOps() string {
  return k.keyOps
}

func (k Oct) Alg() string {
  return k.alg
}

func (k Oct) Kid() string {
  return k.kid
}

func (k Oct) X5u() string {
  return k.x5u
}

func (k Oct) X5c() string {
  return k.x5c
}

func (k Oct) X5t() string {
  return k.x5t
}

func (k Oct) X5tS256() string {
  return k.x5tS256
}

func (k Oct) K() string {
  return k.k
}
