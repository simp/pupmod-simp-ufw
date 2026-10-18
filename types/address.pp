# @summary An address or network for a ufw rule, or `any`
type Ufw::Address = Variant[
  Enum['any'],
  Stdlib::IP::Address::V4,
  Stdlib::IP::Address::V6,
]
