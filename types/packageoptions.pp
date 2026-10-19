# @summary Options for one entry of `ufw::conflicting_packages_entries`
#
# An empty Hash means `{ ensure => present }`. New options are added here as
# Optional keys, so existing data keeps validating.
type Ufw::PackageOptions = Struct[{
  Optional['ensure'] => Enum['present', 'absent'],
}]
