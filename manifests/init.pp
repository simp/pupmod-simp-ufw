# @summary Manage the Uncomplicated Firewall (ufw)
#
# A bare `include ufw` installs the ufw package and does nothing else. Every
# other setting is managed only when its parameter is set; an unset (`undef`)
# parameter leaves the system's current value alone.
#
# Rules are added before the default policies are set, and both before ufw is
# enabled, so that a rule allowing SSH is in place before an incoming `deny`
# policy takes effect.
#
# ### Lockout guard
#
# Catalog compilation fails, unless `allow_lockout` is `true`, when no entry
# in `rules_entries` allows incoming SSH (see `ufw::allows_ssh`) and either:
#
# * `enabled` is `true` and the effective incoming policy denies or rejects.
#   An unset `default_incoming` counts as `deny`, which is ufw's packaged
#   default; set `default_incoming` to `allow` to say otherwise.
# * `default_incoming` is set to `deny` or `reject` and `enabled` isn't
#   `false`. Whether ufw is already active can't be known at compile time,
#   and if it is, the policy takes effect at once.
#
# Removing the rules that allow SSH is guarded the same way: compilation
# fails when an `ensure => absent` entry would allow SSH, no other entry
# does, `enabled` isn't `false` and the incoming policy (unset counting as
# `deny`) isn't `allow`.
#
# Rules that already exist on the node but aren't in `rules_entries` aren't
# considered, since they can't be seen at compile time.
#
# Entries that differ only in `action`, `log` or `comment` fail compilation
# too: ufw keeps a single rule for them, so they would replace each other on
# every run.
#
# @param package_name
#   The ufw package. A `ufw_rule` declared outside this class autorequires
#   `Package['ufw']`, whatever this is set to.
#
# @param service_name
#   The ufw service
#
# @param package_ensure
#   The `ensure` of the ufw package. When unset, `simp_options::package_ensure`
#   is used if it is set, otherwise `installed`.
#
# @param service_ensure
#   The `ensure` of the ufw service. The service is managed only when this or
#   `service_enable` is set. On Ubuntu the service loads the firewall at boot
#   when ufw is enabled.
#
# @param service_enable
#   Whether the ufw service starts at boot
#
# @param enabled
#   `true` enables the firewall (`ufw --force enable`) if it isn't enabled, so
#   it is active now and at boot. `false` disables it (`ufw disable`).
#
# @param default_incoming
#   The default policy for incoming traffic (`ufw default POLICY incoming`)
#
# @param default_outgoing
#   The default policy for outgoing traffic (`ufw default POLICY outgoing`)
#
# @param default_routed
#   The default policy for routed traffic (`ufw default POLICY routed`)
#
# @param logging
#   The logging level (`ufw logging LEVEL`). `on` is satisfied by any level
#   but `off`.
#
# @param ipv6
#   Whether ufw manages IPv6 as well as IPv4 (`IPV6=` in `/etc/default/ufw`).
#   When ufw is enabled, a change is applied with `ufw reload` before any
#   rules are changed.
#
# @param rules_entries
#   ufw rules, each name mapped to the parameters of a `ufw_rule`. Merged
#   across Hiera layers with a deep merge. Every entry must set `action`,
#   including `ensure => absent` entries (ufw only deletes a rule whose action
#   matches), so an incomplete entry fails compilation rather than becoming a
#   broader rule. `ensure => absent` removes a rule; removing an entry from
#   the Hash leaves its rule alone.
#
#   @example
#     ufw::rules_entries:
#       ssh:
#         action: allow
#         to_port: 22
#         proto: tcp
#       allow in on lo:
#         action: allow
#         interface: lo
#       old web rule:
#         ensure: absent
#         action: allow
#         to_port: 80
#         proto: tcp
#
# @param conflicting_packages_entries
#   Packages to manage alongside ufw, each mapped to its options. Packages
#   that conflict with ufw, such as `iptables-persistent`, can be removed with
#   `{ ensure => absent }`; they are removed before ufw is installed. Nothing
#   is removed by default.
#
# @param allow_lockout
#   Allow enabling ufw with a denying incoming policy and no rule in
#   `rules_entries` that allows SSH. See "Lockout guard" above.
#
# @param lockout_guard_port
#   The SSH port the lockout guard looks for in `rules_entries`
#
# @example Install ufw only
#   include ufw
#
# @example A typical hardened configuration
#   class { 'ufw':
#     enabled          => true,
#     service_ensure   => 'running',
#     service_enable   => true,
#     default_incoming => 'deny',
#     default_outgoing => 'deny',
#     default_routed   => 'deny',
#     logging          => 'low',
#     rules_entries    => {
#       'ssh'        => { 'action' => 'allow', 'to_port' => 22, 'proto' => 'tcp' },
#       'lo in'      => { 'action' => 'allow', 'interface' => 'lo' },
#       'lo out'     => { 'action' => 'allow', 'interface' => 'lo', 'direction' => 'out' },
#       'deny 127/8' => { 'action' => 'deny', 'from' => '127.0.0.0/8' },
#       'deny ::1'   => { 'action' => 'deny', 'from' => '::1' },
#       'dns out'    => { 'action' => 'allow', 'direction' => 'out', 'to_port' => 53 },
#     },
#   }
#
class ufw (
  String[1]                            $package_name,
  String[1]                            $service_name,
  Optional[String[1]]                  $package_ensure               = undef,
  Optional[Stdlib::Ensure::Service]    $service_ensure               = undef,
  Optional[Boolean]                    $service_enable               = undef,
  Optional[Boolean]                    $enabled                      = undef,
  Optional[Ufw::Policy]                $default_incoming             = undef,
  Optional[Ufw::Policy]                $default_outgoing             = undef,
  Optional[Ufw::Policy]                $default_routed               = undef,
  Optional[Ufw::LogLevel]              $logging                      = undef,
  Optional[Boolean]                    $ipv6                         = undef,
  Hash[String[1], Ufw::RuleOptions]    $rules_entries                = {},
  Hash[String[1], Ufw::PackageOptions] $conflicting_packages_entries = {},
  Boolean                              $allow_lockout                = false,
  Stdlib::Port                         $lockout_guard_port           = 22,
) {
  $_no_action = $rules_entries.filter |$name, $opts| { $opts['action'] =~ Undef }.keys
  unless $_no_action.empty {
    fail(@("FAIL"/L)
      ufw: every ufw::rules_entries entry needs an 'action' (allow, deny, reject or limit),       including 'ensure: absent' entries. Missing in: ${_no_action.sort.join(', ')}
      |-FAIL
    )
  }

  $_incoming = pick($default_incoming, 'deny')
  $_lockout_action = $_incoming ? {
    'allow' => undef,
    default => $enabled ? {
      true    => "enable ufw with a '${_incoming}' incoming policy and",
      false   => undef,
      default => $default_incoming ? {
        undef   => undef,
        default => "set a '${_incoming}' incoming policy, which applies at once if ufw is active, with",
      },
    },
  }
  $_allows_ssh = ufw::allows_ssh($rules_entries, $lockout_guard_port)
  if $_lockout_action and !$allow_lockout and !$_allows_ssh {
    fail(@("FAIL"/L)
      ufw: refusing to ${_lockout_action} no \
      ufw::rules_entries entry allowing SSH (port ${lockout_guard_port}/tcp or the OpenSSH app). \
      Add one, or set ufw::allow_lockout to true if access is allowed some other way.
      |-FAIL
    )
  }

  # Removing the only rules that allow SSH locks out a node where ufw is
  # already active with a denying policy, which can't be ruled out here.
  $_removed_ssh = $rules_entries.filter |$name, $opts| {
    $opts['ensure'] == 'absent' and ufw::allows_ssh({ $name => $opts + { 'ensure' => 'present' } }, $lockout_guard_port)
  }.keys
  if $enabled != false and $_incoming != 'allow' and !$allow_lockout and !$_allows_ssh and !$_removed_ssh.empty {
    fail(@("FAIL"/L)
      ufw: refusing to remove the ufw::rules_entries ${_removed_ssh.sort.join(', ')} allowing SSH \
      with a '${_incoming}' incoming policy and no other entry allowing SSH \
      (port ${lockout_guard_port}/tcp or the OpenSSH app). \
      Add one, or set ufw::allow_lockout to true if access is allowed some other way.
      |-FAIL
    )
  }

  # ufw keeps one rule for entries that differ only in action, log type or
  # comment, replacing it in place, so such entries would undo each other
  # on every run.
  $_rule_keys = $rules_entries.filter |$name, $opts| { pick($opts['ensure'], 'present') == 'present' }.map |$name, $opts| {
    $_key = {
      'route'         => $opts['route'] ? { undef => false, default => $opts['route'] },
      'direction'     => pick($opts['direction'], 'in'),
      'interface'     => $opts['interface'],
      'out_interface' => $opts['out_interface'],
      'proto'         => pick($opts['proto'], 'any'),
      'from'          => downcase(String(pick($opts['from'], 'any'))),
      'to'            => downcase(String(pick($opts['to'], 'any'))),
      'from_app'      => $opts['from_app'].then |$app| { downcase($app) },
      'to_app'        => $opts['to_app'].then |$app| { downcase($app) },
    } + ['from_port', 'to_port'].reduce({}) |$memo, $param| {
      $memo + {
        $param => $opts[$param] ? {
          undef   => undef,
          Array   => $opts[$param].map |$p| { String($p) }.sort.join(','),
          default => String($opts[$param]).split(',').sort.join(','),
        },
      }
    }
    [String($_key), $name]
  }
  $_same_rule = $_rule_keys.reduce({}) |$memo, $pair| {
    $memo + { $pair[0] => ($memo[$pair[0]] ? { undef => [], default => $memo[$pair[0]] }) + [$pair[1]] }
  }.filter |$key, $names| { $names.length > 1 }.map |$key, $names| { $names.sort.join(' and ') }
  unless $_same_rule.empty {
    fail(@("FAIL"/L)
      ufw: these ufw::rules_entries describe the same ufw rule, differing at most in action, log or comment, \
      and would replace each other on every run: ${_same_rule.sort.join('; ')}
      |-FAIL
    )
  }

  # ufw's own files. Their paths are compiled into ufw, and the ufw_rule
  # provider reads the same ones.
  $_defaults_file = '/etc/default/ufw'
  $_conf_file = '/etc/ufw/ufw.conf'

  $conflicting_packages_entries.each |$pkg, $opts| {
    if pick($opts['ensure'], 'present') == 'absent' {
      package { $pkg:
        ensure => 'absent',
        before => Package[$package_name],
      }
    } else {
      package { $pkg:
        ensure => 'installed',
      }
    }
  }

  package { $package_name:
    ensure => pick($package_ensure, lookup('simp_options::package_ensure', { 'default_value' => 'installed' })),
  }

  $_exec = { 'path' => ['/usr/sbin', '/usr/bin', '/sbin', '/bin'] }

  # Resources run in this order: rules, default policies, logging, enabling
  # or disabling, and the service. Only the ones whose parameter is set are
  # declared.
  $_policies = {
    'incoming' => ['DEFAULT_INPUT_POLICY', $default_incoming],
    'outgoing' => ['DEFAULT_OUTPUT_POLICY', $default_outgoing],
    'routed'   => ['DEFAULT_FORWARD_POLICY', $default_routed],
  }.filter |$direction, $setting| { $setting[1] =~ NotUndef }

  $_state_execs = $enabled ? {
    true    => [Exec['ufw-enable']],
    false   => [Exec['ufw-disable']],
    default => [],
  }
  $_logging_execs = $logging ? {
    undef   => [],
    default => [Exec['ufw-logging']],
  }
  $_policy_execs = $_policies.keys.map |$direction| { Exec["ufw-default-${direction}"] }

  if $ipv6 =~ NotUndef {
    $_ipv6 = $ipv6 ? { true => 'yes', default => 'no' }

    file_line { 'ufw IPV6':
      path    => $_defaults_file,
      line    => "IPV6=${_ipv6}",
      match   => '^IPV6=',
      require => Package[$package_name],
      notify  => Exec['ufw-reload'],
    }

    # Applies the IPv6 setting to an enabled firewall before rules change
    exec { 'ufw-reload':
      command     => 'ufw reload',
      onlyif      => "grep -qx 'ENABLED=yes' ${_conf_file}",
      refreshonly => true,
      before      => $_policy_execs + $_logging_execs + $_state_execs,
      *           => $_exec,
    }
  }

  $rules_entries.each |$name, $opts| {
    ufw_rule { $name:
      require => Package[$package_name],
      before  => $_policy_execs + $_logging_execs + $_state_execs,
      *       => $opts,
    }
  }

  $_targets = { 'allow' => 'ACCEPT', 'deny' => 'DROP', 'reject' => 'REJECT' }

  $_policies.each |$direction, $setting| {
    [$key, $policy] = $setting

    exec { "ufw-default-${direction}":
      command => "ufw default ${policy} ${direction}",
      unless  => "grep -Eqx '${key}=\"?${_targets[$policy]}\"?' ${_defaults_file}",
      require => Package[$package_name],
      before  => $_logging_execs + $_state_execs,
      *       => $_exec,
    }
  }

  if $logging =~ NotUndef {
    $_level = $logging ? {
      'on'    => '(low|medium|high|full)',
      default => $logging,
    }

    exec { 'ufw-logging':
      command => "ufw logging ${logging}",
      unless  => "grep -Eqx 'LOGLEVEL=${_level}' ${_conf_file}",
      require => Package[$package_name],
      before  => $_state_execs,
      *       => $_exec,
    }
  }

  if $enabled == true {
    exec { 'ufw-enable':
      command => 'ufw --force enable',
      unless  => "grep -qx 'ENABLED=yes' ${_conf_file}",
      require => Package[$package_name],
      *       => $_exec,
    }
  } elsif $enabled == false {
    exec { 'ufw-disable':
      command => 'ufw disable',
      onlyif  => "grep -qx 'ENABLED=yes' ${_conf_file}",
      require => Package[$package_name],
      *       => $_exec,
    }
  }

  if $service_ensure =~ NotUndef or $service_enable =~ NotUndef {
    service { $service_name:
      ensure  => $service_ensure,
      enable  => $service_enable,
      require => [Package[$package_name]] + $_state_execs,
    }
  }
}
