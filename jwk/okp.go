package jwk

type OkpKey interface {
  Jwk
  Crv() string
  D() string
  X() string
}

type Okp struct {
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
  // okp fields
  crv string
  d string
  x string
}

func (k Okp) Kty() string {
  return k.kty
}

func (k Okp) Use() string {
  return k.use
}

func (k Okp) KeyOps() string {
  return k.keyOps
}

func (k Okp) Alg() string {
  return k.alg
}

func (k Okp) Kid() string {
  return k.kid
}

func (k Okp) X5u() string {
  return k.x5u
}

func (k Okp) X5c() string {
  return k.x5c
}

func (k Okp) X5t() string {
  return k.x5t
}

func (k Okp) X5tS256() string {
  return k.x5tS256
}

func (k Okp) Crv() string {
  return k.crv
}

func (k Okp) D() string {
  return k.d
}

func (k Okp) X() string {
  return k.x
}
