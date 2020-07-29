package jwk

type EcKey interface {
  EcPublicKey
}

type EcPublicKey interface {
  Jwk
  Crv() string
  X() string
  Y() string
}

type EcPrivateKey interface {
  EcPublicKey
  D() string
}

type EcPublic struct {
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
  // ec public fields
  crv string
  x string
  y string
}

func (k EcPublic) Kty() string {
  return k.kty
}

func (k EcPublic) Use() string {
  return k.use
}

func (k EcPublic) KeyOps() string {
  return k.keyOps
}

func (k EcPublic) Alg() string {
  return k.alg
}

func (k EcPublic) Kid() string {
  return k.kid
}

func (k EcPublic) X5u() string {
  return k.x5u
}

func (k EcPublic) X5c() string {
  return k.x5c
}

func (k EcPublic) X5t() string {
  return k.x5t
}

func (k EcPublic) X5tS256() string {
  return k.x5tS256
}

func (k EcPublic) Crv() string {
  return k.crv
}

func (k EcPublic) X() string {
  return k.x
}

func (k EcPublic) Y() string {
  return k.y
}

type EcPrivate struct {
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
  // ec public fields
  crv string
  x string
  y string
  // ec private fields
  d string
}

func (k EcPrivate) Kty() string {
  return k.kty
}

func (k EcPrivate) Use() string {
  return k.use
}

func (k EcPrivate) KeyOps() string {
  return k.keyOps
}

func (k EcPrivate) Alg() string {
  return k.alg
}

func (k EcPrivate) Kid() string {
  return k.kid
}

func (k EcPrivate) X5u() string {
  return k.x5u
}

func (k EcPrivate) X5c() string {
  return k.x5c
}

func (k EcPrivate) X5t() string {
  return k.x5t
}

func (k EcPrivate) X5tS256() string {
  return k.x5tS256
}

func (k EcPrivate) Crv() string {
  return k.crv
}

func (k EcPrivate) X() string {
  return k.x
}

func (k EcPrivate) Y() string {
  return k.y
}

func (k EcPrivate) D() string {
  return k.d
}
