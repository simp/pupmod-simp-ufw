# @summary A port or port range (`8000:8100`) for a ufw rule
type Ufw::Port = Variant[
  Integer[1, 65535],
  Pattern[/\A[1-9]\d{0,4}(:[1-9]\d{0,4})?\z/],
]
