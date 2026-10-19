# @summary One or more ports or port ranges for a ufw rule
#
# A single port or range, a comma-separated String of them, or an Array.
type Ufw::Ports = Variant[
  Ufw::Port,
  Pattern[/\A[1-9]\d{0,4}(:[1-9]\d{0,4})?(,[1-9]\d{0,4}(:[1-9]\d{0,4})?)+\z/],
  Array[Ufw::Port, 1, 15],
]
