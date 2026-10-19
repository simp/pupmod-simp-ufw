# @summary Whether a set of `ufw::rules_entries` allows incoming SSH
#
# Used by the lockout guard in class `ufw`. A rule counts when it is not
# `absent`, is an `allow` or `limit` rule for incoming (not routed) traffic,
# with protocol `tcp` or `any`, and either uses the `OpenSSH` application
# profile, includes `$port` in its `to_port`, or has no port or application
# restriction at all (so it applies to every port). Rules restricted to a source network
# or an interface count, except rules for the loopback interface (`lo`) or
# a loopback source or destination (`127.0.0.0/8`, `::1`), which don't give
# remote access.
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
    $_all_ports = ['to_port', 'to_app', 'from_port', 'from_app'].all |$param| { $opts[$param] =~ Undef }

    $_loopback = $opts['interface'] == 'lo' or [$opts['from'], $opts['to']].any |$addr| {
      $addr =~ String and ($addr =~ /\A127\./ or $addr in ['::1', '::1/128'])
    }

    (
      pick($opts['ensure'], 'present') == 'present'
      and $opts['action'] in ['allow', 'limit']
      and !pick($opts['route'], false)
      and pick($opts['direction'], 'in') == 'in'
      and !$_loopback
      and (
        $opts['to_app'] == 'OpenSSH'
        or (($_port_match or $_all_ports) and pick($opts['proto'], 'any') in ['tcp', 'any'])
      )
    )
  }
}
