package jwk

const OkpType = "OKP"

type OkpBuilder struct {
  Okp Okp
}

func NewOkpBuilder() *OkpBuilder {
  return &OkpBuilder{}
}

func (b *OkpBuilder) Use(value string) *OkpBuilder {
  b.Okp.use = value
  return b
}

func (b *OkpBuilder) KeyOps(value []string) *OkpBuilder {
  b.Okp.keyOps = value
  return b
}

func (b *OkpBuilder) Alg(value string) *OkpBuilder {
  b.Okp.alg = value
  return b
}

func (b *OkpBuilder) Kid(value string) *OkpBuilder {
  b.Okp.kid = value
  return b
}

func (b *OkpBuilder) X5u(value string) *OkpBuilder {
  b.Okp.x5u = value
  return b
}

func (b *OkpBuilder) X5c(value string) *OkpBuilder {
  b.Okp.x5c = value
  return b
}

func (b *OkpBuilder) X5t(value string) *OkpBuilder {
  b.Okp.x5t = value
  return b
}

func (b *OkpBuilder) X5tS256(value string) *OkpBuilder {
  b.Okp.x5tS256 = value
  return b
}

func (b *OkpBuilder) Crv(value string) *OkpBuilder {
  b.Okp.crv = value
  return b
}

func (b *OkpBuilder) D(value string) *OkpBuilder {
  b.Okp.d = value
  return b
}

func (b *OkpBuilder) X(value string) *OkpBuilder {
  b.Okp.x = value
  return b
}

func (b *OkpBuilder) Build() Okp {
  b.Okp.kty = OkpType

  return b.Okp
}
