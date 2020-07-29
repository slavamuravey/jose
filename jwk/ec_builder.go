package jwk

const EcType = "EC"

type EcPublicBuilder struct {
  ecPublic EcPublic
}

func NewEcPublicBuilder() *EcPublicBuilder {
  return &EcPublicBuilder{}
}

func (b *EcPublicBuilder) Use(value string) *EcPublicBuilder {
  b.ecPublic.use = value
  return b
}

func (b *EcPublicBuilder) KeyOps(value string) *EcPublicBuilder {
  b.ecPublic.keyOps = value
  return b
}

func (b *EcPublicBuilder) Alg(value string) *EcPublicBuilder {
  b.ecPublic.alg = value
  return b
}

func (b *EcPublicBuilder) Kid(value string) *EcPublicBuilder {
  b.ecPublic.kid = value
  return b
}

func (b *EcPublicBuilder) X5u(value string) *EcPublicBuilder {
  b.ecPublic.x5u = value
  return b
}

func (b *EcPublicBuilder) X5c(value string) *EcPublicBuilder {
  b.ecPublic.x5c = value
  return b
}

func (b *EcPublicBuilder) X5t(value string) *EcPublicBuilder {
  b.ecPublic.x5t = value
  return b
}

func (b *EcPublicBuilder) X5tS256(value string) *EcPublicBuilder {
  b.ecPublic.x5tS256 = value
  return b
}

func (b *EcPublicBuilder) Crv(value string) *EcPublicBuilder {
  b.ecPublic.crv = value
  return b
}

func (b *EcPublicBuilder) X(value string) *EcPublicBuilder {
  b.ecPublic.x = value
  return b
}

func (b *EcPublicBuilder) Y(value string) *EcPublicBuilder {
  b.ecPublic.y = value
  return b
}

func (b *EcPublicBuilder) Build() EcPublic {
  b.ecPublic.kty = EcType

  return b.ecPublic
}

type EcPrivateBuilder struct {
  ecPrivate EcPrivate
}

func NewEcPrivateBuilder() *EcPrivateBuilder {
  return &EcPrivateBuilder{}
}

func (b *EcPrivateBuilder) Use(value string) *EcPrivateBuilder {
  b.ecPrivate.use = value
  return b
}

func (b *EcPrivateBuilder) KeyOps(value string) *EcPrivateBuilder {
  b.ecPrivate.keyOps = value
  return b
}

func (b *EcPrivateBuilder) Alg(value string) *EcPrivateBuilder {
  b.ecPrivate.alg = value
  return b
}

func (b *EcPrivateBuilder) Kid(value string) *EcPrivateBuilder {
  b.ecPrivate.kid = value
  return b
}

func (b *EcPrivateBuilder) X5u(value string) *EcPrivateBuilder {
  b.ecPrivate.x5u = value
  return b
}

func (b *EcPrivateBuilder) X5c(value string) *EcPrivateBuilder {
  b.ecPrivate.x5c = value
  return b
}

func (b *EcPrivateBuilder) X5t(value string) *EcPrivateBuilder {
  b.ecPrivate.x5t = value
  return b
}

func (b *EcPrivateBuilder) X5tS256(value string) *EcPrivateBuilder {
  b.ecPrivate.x5tS256 = value
  return b
}

func (b *EcPrivateBuilder) Crv(value string) *EcPrivateBuilder {
  b.ecPrivate.crv = value
  return b
}

func (b *EcPrivateBuilder) X(value string) *EcPrivateBuilder {
  b.ecPrivate.x = value
  return b
}

func (b *EcPrivateBuilder) Y(value string) *EcPrivateBuilder {
  b.ecPrivate.y = value
  return b
}

func (b *EcPrivateBuilder) D(value string) *EcPrivateBuilder {
  b.ecPrivate.y = value
  return b
}

func (b *EcPrivateBuilder) Build() EcPrivate {
  b.ecPrivate.kty = EcType

  return b.ecPrivate
}
