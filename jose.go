package jose

type Jwt interface {
  Payload() string
}
