package jwk

const OctType = "oct"

type OctBuilder struct {
  Oct Oct
}

func NewOctBuilder() *OctBuilder {
  return &OctBuilder{}
}

func (b *OctBuilder) Use(value string) *OctBuilder {
  b.Oct.use = value
  return b
}

func (b *OctBuilder) KeyOps(value []string) *OctBuilder {
  b.Oct.keyOps = value
  return b
}

func (b *OctBuilder) Alg(value string) *OctBuilder {
  b.Oct.alg = value
  return b
}

func (b *OctBuilder) Kid(value string) *OctBuilder {
  b.Oct.kid = value
  return b
}

func (b *OctBuilder) X5u(value string) *OctBuilder {
  b.Oct.x5u = value
  return b
}

func (b *OctBuilder) X5c(value string) *OctBuilder {
  b.Oct.x5c = value
  return b
}

func (b *OctBuilder) X5t(value string) *OctBuilder {
  b.Oct.x5t = value
  return b
}

func (b *OctBuilder) X5tS256(value string) *OctBuilder {
  b.Oct.x5tS256 = value
  return b
}

func (b *OctBuilder) K(value string) *OctBuilder {
  b.Oct.k = value
  return b
}

func (b *OctBuilder) Build() Oct {
  b.Oct.kty = OctType

  return b.Oct
}
