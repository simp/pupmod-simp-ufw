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
# When `enabled` is `true`, the effective incoming policy denies or rejects,
# and no entry in `rules_entries` allows incoming SSH (see
# `ufw::allows_ssh`), catalog compilation fails, unless `allow_lockout` is
# `true`. An unset `default_incoming` counts as `deny`, which is ufw's
# packaged default; set `default_incoming` to `allow` to say otherwise. Rules
# that already exist on the node but aren't in `rules_entries` aren't
# considered, since they can't be seen at compile time.
#
# @param package_name
#   The ufw package
#
# @param service_name
#   The ufw service
#
# @param ufw_command
#   The path to the `ufw` command
#
# @param defaults_file
#   ufw's defaults file, which holds the default policies and the IPv6 setting
#
# @param conf_file
#   ufw's configuration file, which holds the enabled state and logging level
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
#   Whether ufw manages IPv6 as well as IPv4 (`IPV6=` in `defaults_file`).
#   When ufw is enabled, a change is applied with `ufw reload` before any
#   rules are changed.
#
# @param rules_entries
#   ufw rules, each name mapped to the parameters of a `ufw_rule`. Merged
#   across Hiera layers with a deep merge. `ensure => absent` removes a rule;
#   removing an entry from the Hash leaves its rule alone.
#
#   @example
#     ufw::rules_entries:
#       ssh:
#         to_port: 22
#         proto: tcp
#       allow in on lo:
#         interface: lo
#       old web rule:
#         ensure: absent
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
#       'ssh'           => { 'to_port' => 22, 'proto' => 'tcp' },
#       'lo in'         => { 'interface' => 'lo' },
#       'lo out'        => { 'interface' => 'lo', 'direction' => 'out' },
#       'deny 127/8'    => { 'action' => 'deny', 'from' => '127.0.0.0/8' },
#       'deny ::1'      => { 'action' => 'deny', 'from' => '::1' },
#       'dns out'       => { 'direction' => 'out', 'to_port' => 53 },
#     },
#   }
#
class ufw (
  String[1]                            $package_name,
  String[1]                            $service_name,
  Stdlib::Absolutepath                 $ufw_command,
  Stdlib::Absolutepath                 $defaults_file,
  Stdlib::Absolutepath                 $conf_file,
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
  if $enabled == true and !$allow_lockout and pick($default_incoming, 'deny') != 'allow' {
    unless ufw::allows_ssh($rules_entries, $lockout_guard_port) {
      fail(@("FAIL"/L)
        ufw: refusing to enable ufw with a '${pick($default_incoming, 'deny')}' incoming policy and no \
        ufw::rules_entries entry allowing SSH (port ${lockout_guard_port}/tcp or the OpenSSH app). \
        Add one, or set ufw::allow_lockout to true if access is allowed some other way.
        |-FAIL
      )
    }
  }

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

  $_grep = { 'path' => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'] }

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
      path    => $defaults_file,
      line    => "IPV6=${_ipv6}",
      match   => '^IPV6=',
      require => Package[$package_name],
      notify  => Exec['ufw-reload'],
    }

    # Applies the IPv6 setting to an enabled firewall before rules change
    exec { 'ufw-reload':
      command     => "${ufw_command} reload",
      onlyif      => "grep -qx 'ENABLED=yes' ${conf_file}",
      refreshonly => true,
      before      => $_policy_execs + $_logging_execs + $_state_execs,
      *           => $_grep,
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
      command => "${ufw_command} default ${policy} ${direction}",
      unless  => "grep -Eqx '${key}=\"?${_targets[$policy]}\"?' ${defaults_file}",
      require => Package[$package_name],
      before  => $_logging_execs + $_state_execs,
      *       => $_grep,
    }
  }

  if $logging =~ NotUndef {
    $_level = $logging ? {
      'on'    => '(low|medium|high|full)',
      default => $logging,
    }

    exec { 'ufw-logging':
      command => "${ufw_command} logging ${logging}",
      unless  => "grep -Eqx 'LOGLEVEL=${_level}' ${conf_file}",
      require => Package[$package_name],
      before  => $_state_execs,
      *       => $_grep,
    }
  }

  if $enabled == true {
    exec { 'ufw-enable':
      command => "${ufw_command} --force enable",
      unless  => "grep -qx 'ENABLED=yes' ${conf_file}",
      require => Package[$package_name],
      *       => $_grep,
    }
  } elsif $enabled == false {
    exec { 'ufw-disable':
      command => "${ufw_command} disable",
      onlyif  => "grep -qx 'ENABLED=yes' ${conf_file}",
      require => Package[$package_name],
      *       => $_grep,
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
