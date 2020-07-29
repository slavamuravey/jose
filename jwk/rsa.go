package jwk

const RsaType = "RSA"

type RsaKey interface {
  RsaPublicKey
}

type RsaPublicKey interface {
  Jwk
  N() string
  E() string
}

type RsaPrivateKey interface {
  RsaPublicKey
  D() string
  P() string
  Q() string
  Dp() string
  Dq() string
  Qi() string
  Oth() Oth
}

type Oth struct {
  R string
  D string
  T string
}
