# @summary Whether a set of `ufw::rules_entries` allows incoming SSH
#
# Used by the lockout guard in class `ufw`. A rule counts when it is not
# `absent`, is an `allow` or `limit` rule for incoming (not routed) traffic,
# and either uses the `OpenSSH` application profile or includes `$port` in
# its `to_port` with protocol `tcp` or `any`. Rules restricted to a source
# address or interface count too.
#
# @param rules
#   The rules, as for `ufw::rules_entries`
#
# @param port
#   The SSH port
#
# @return [Boolean]
function ufw::allows_ssh(
  Hash[String[1], Ufw::RuleOptions] $rules,
  Stdlib::Port                      $port = 22,
) >> Boolean {
  $rules.any |$name, $opts| {
    $_ports = $opts['to_port'] ? {
      undef   => [],
      Array   => $opts['to_port'].map |$p| { String($p) },
      default => String($opts['to_port']).split(','),
    }

    $_port_match = $_ports.any |$p| {
      $_range = $p.split(':').map |$n| { Integer($n) }
      $_range.length ? {
        1       => $_range[0] == $port,
        default => $port >= $_range[0] and $port <= $_range[1],
      }
    }

    (
      pick($opts['ensure'], 'present') == 'present'
      and pick($opts['action'], 'allow') in ['allow', 'limit']
      and !pick($opts['route'], false)
      and pick($opts['direction'], 'in') == 'in'
      and (
        $opts['to_app'] == 'OpenSSH'
        or ($_port_match and pick($opts['proto'], 'any') in ['tcp', 'any'])
      )
    )
  }
}
