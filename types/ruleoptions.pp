# @summary Options for one entry of `ufw::rules_entries`
#
# Each key is a parameter of the `ufw_rule` type. `action` is required,
# including for `ensure => absent` entries, since ufw only deletes a rule
# whose action matches. Class `ufw` fails compilation for an entry without
# one, naming the entry, so a partly written entry can't turn into a rule
# that allows all traffic. (The key is optional here only so that an empty
# entry gets that message rather than Puppet's "expects size to be between
# 1 and 15, got 0".)
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
