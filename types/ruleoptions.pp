# @summary Options for one entry of `ufw::rules_entries`
#
# Each key is a parameter of the `ufw_rule` type. An empty Hash is an
# `allow` rule for all incoming traffic, so every real rule sets at least
# one of the matching options.
type Ufw::RuleOptions = Struct[{
  Optional['ensure']        => Enum['present', 'absent'],
  Optional['action']        => Enum['allow', 'deny', 'reject', 'limit'],
  Optional['route']         => Boolean,
  Optional['direction']     => Enum['in', 'out'],
  Optional['interface']     => Ufw::Interface,
  Optional['out_interface'] => Ufw::Interface,
  Optional['log']           => Enum['log', 'log-all'],
  Optional['proto']         => Ufw::Protocol,
  Optional['from']          => Ufw::Address,
  Optional['to']            => Ufw::Address,
  Optional['from_port']     => Ufw::Ports,
  Optional['to_port']       => Ufw::Ports,
  Optional['from_app']      => Ufw::AppName,
  Optional['to_app']        => Ufw::AppName,
  Optional['comment']       => Ufw::Comment,
}]
