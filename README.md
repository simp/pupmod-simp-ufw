[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/73/badge)](https://bestpractices.coreinfrastructure.org/projects/73)
[![Puppet Forge](https://img.shields.io/puppetforge/v/simp/ufw.svg)](https://forge.puppetlabs.com/simp/ufw)
[![Puppet Forge Downloads](https://img.shields.io/puppetforge/dt/simp/ufw.svg)](https://forge.puppetlabs.com/simp/ufw)

#### Table of Contents

1. [Description](#description)
2. [Setup - The basics of getting started with ufw](#setup)
    * [What ufw affects](#what-ufw-affects)
    * [Beginning with ufw](#beginning-with-ufw)
3. [Usage - Configuration options and additional functionality](#usage)
    * [Rules](#rules)
    * [The lockout guard](#the-lockout-guard)
    * [Compliance controls](#compliance-controls)
4. [Limitations - OS compatibility, etc.](#limitations)
5. [Development - Guide for contributing to the module](#development)
      * [Acceptance Tests - Beaker env variables](#acceptance-tests)

## Description

This module manages the Uncomplicated Firewall (ufw) on Ubuntu: the package,
whether the firewall is enabled, its default policies, logging level, IPv6
support, service and rules.

A bare `include ufw` **only installs the package**. Every other setting is
managed only when its parameter is set, and an unset parameter leaves the
system's current value alone. A later Puppet run that stops setting a
parameter, or a rule, leaves what an earlier run applied in place; to remove
a rule, set it to `ensure => absent`.

See [REFERENCE.md](./REFERENCE.md) for additional information.

### This is a SIMP module

This module is a component of the [System Integrity Management Platform](https://simp-project.com),
a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our [issue tracker](https://github.com/simp/pupmod-simp-ufw/issues).

Please read our [Contribution Guide](https://simp.readthedocs.io/en/stable/contributors_guide/index.html)

This module is optimally designed for use within a larger SIMP ecosystem, but it can be used independently:
* When included within the SIMP ecosystem, security compliance settings will be managed from the Puppet server.
* If used independently, all SIMP-managed security subsystems are disabled by default and must be explicitly opted into by administrators.  Please review the simp_options module for details.

## Setup

### What ufw affects

* installs the `ufw` package
* only when the matching parameter is set:
  * enables or disables the firewall (`ufw --force enable` / `ufw disable`)
  * sets the default incoming, outgoing and routed policies (`ufw default`)
  * sets the logging level (`ufw logging`)
  * sets `IPV6=` in `/etc/default/ufw`
  * adds and removes rules (`ufw [route] [delete] ...`)
  * manages the `ufw` service
  * installs or removes other packages, such as `iptables-persistent`

Settings are changed with the `ufw` command, so they take effect in a
running firewall straight away, whether or not the service is managed. Rules
are added before the default policies are changed, and both before the
firewall is enabled.

### Beginning with ufw

To install the package, just include the class:

```puppet
include ufw
```

## Usage

A typical hardened configuration, in Hiera:

```yaml
ufw::enabled: true
ufw::service_ensure: running
ufw::service_enable: true
ufw::default_incoming: deny
ufw::default_outgoing: deny
ufw::default_routed: deny
ufw::logging: low
ufw::rules_entries:
  ssh:
    action: allow
    to_port: 22
    proto: tcp
  loopback in:
    action: allow
    interface: lo
  loopback out:
    action: allow
    interface: lo
    direction: out
  deny spoofed loopback v4:
    action: deny
    from: 127.0.0.0/8
  deny spoofed loopback v6:
    action: deny
    from: '::1'
  dns out:
    action: allow
    direction: out
    to_port: 53
  web out:
    action: allow
    direction: out
    to_port: [80, 443]
    proto: tcp
```

### Rules

Each entry of `ufw::rules_entries` maps a name to the parameters of a
`ufw_rule` resource, which can also be declared directly:

```puppet
ufw_rule { 'web from the office':
  action  => 'allow',
  from    => '192.0.2.0/24',
  to_port => [80, 443],
  proto   => 'tcp',
  comment => 'office web access',
}
```

The parameters follow ufw's extended rule syntax: `action` (`allow`, `deny`,
`reject` or `limit`; required), `route` (a `ufw route` rule), `direction` (`in` or
`out`), `interface` (and `out_interface` for routed rules), `log` (`log` or
`log-all`), `proto`, `from`, `to`, `from_port`, `to_port`, `from_app`,
`to_app` (an application profile such as `OpenSSH`) and `comment`. Unknown
keys and invalid values in `ufw::rules_entries` fail catalog compilation.

`action` has no default and is required in every entry, including
`ensure: absent` ones, since ufw only deletes a rule whose action matches. An
incomplete entry (for example `{}`, or one whose `action` a higher Hiera layer
didn't supply) therefore fails compilation instead of becoming a rule that
allows everything. A rule that allows all incoming traffic has to say so:

```yaml
ufw::rules_entries:
  allow everything in:
    action: allow
```

`ufw::rules_entries` is merged across Hiera layers with a deep merge, so a
layer can add a rule or remove one (`ensure: absent`) without restating the
others. Deleting an entry stops Puppet managing the rule but leaves it in
place. Removing a rule takes the options it was added with, `action`
included:

```yaml
ufw::rules_entries:
  old web rule:
    ensure: absent
    action: allow
    to_port: 80
    proto: tcp
```

Rules are matched against ufw's own rule store (`/etc/ufw/user.rules` and
`user6.rules`) in ufw's normalized form, so a rule added by hand in an
equivalent form, such as `ufw allow ssh/tcp` for `to_port: 22, proto: tcp`,
is recognized. A rule without an address applies to IPv4 and, when IPv6 is
enabled, IPv6, and Puppet adds it to whichever is missing it. Changing a
rule's `action`, `log` or `comment` makes ufw replace the existing rule in
place, keeping its position.

Rules are added at the end of ufw's rule list; this module doesn't manage
rule order.

### The lockout guard

Enabling ufw with an incoming policy that denies traffic, and no rule
allowing SSH, would cut off remote access. When `ufw::enabled` is `true`,
catalog compilation fails unless one of these holds:

* `ufw::default_incoming` is `allow`;
* an entry in `ufw::rules_entries` allows incoming SSH: an `allow` or `limit`
  rule for incoming, non-routed traffic to `ufw::lockout_guard_port`
  (default `22`) with protocol `tcp` or `any`, or for the `OpenSSH`
  application profile. A rule restricted to a source network or interface
  counts;
* `ufw::allow_lockout` is `true`.

An unset `ufw::default_incoming` counts as `deny`, which is ufw's packaged
default. Rules that exist on the node but aren't in `ufw::rules_entries`
can't be seen at compile time and don't count; set `ufw::allow_lockout` when
SSH is allowed that way.

### Compliance controls

The parameters cover these DISA STIG and CIS controls for Ubuntu:

| Control | Parameters |
|---|---|
| ufw is installed (STIG V-270654) | `include ufw` |
| ufw is enabled and its service enabled and running (STIG V-270655) | `enabled`, `service_ensure`, `service_enable` |
| `iptables-persistent` is not installed | `conflicting_packages_entries: { iptables-persistent: { ensure: absent } }` |
| loopback traffic is configured | `rules_entries` (see the example above) |
| outbound connections are configured | `rules_entries` with `direction: out` |
| rules exist for all open ports | `rules_entries` |
| the default policy is deny | `default_incoming`, `default_outgoing`, `default_routed` |
| logging is enabled | `logging` |

## Limitations

This module supports Ubuntu 22.04 and 24.04. Please see the
[`metadata.json` file](./metadata.json) for the most up-to-date list of
supported operating systems, Puppet versions, and module dependencies.

* Rule order isn't managed: new rules are appended.
* `ufw status verbose` shows the routed policy as `disabled` while the kernel
  doesn't forward packets; `ufw::default_routed` is still stored and applies
  once forwarding is turned on.
* ufw doesn't allow `'` in rule comments.
* Changing `ufw::ipv6` on an enabled firewall runs `ufw reload`. Rules with
  IPv6 addresses need IPv6 enabled.

## Development

Please see the [SIMP Contribution Guidelines](https://simp.readthedocs.io/en/stable/contributors_guide/index.html).

### Acceptance tests

This module includes [Beaker](https://github.com/puppetlabs/beaker) acceptance tests using the SIMP [Beaker Helpers](https://github.com/simp/rubygem-simp-beaker-helpers).  The tests use [Vagrant](https://www.vagrantup.com/); CI runs them with the `vagrant-libvirt` provider. To execute the tests run the following:

```shell
bundle install
BEAKER_HYPERVISOR=vagrant_libvirt bundle exec rake beaker:suites[default,ubuntu2404]
BEAKER_HYPERVISOR=vagrant_libvirt bundle exec rake beaker:suites[default,ubuntu2204]
```

The `bento/ubuntu-22.04` libvirt box boots with UEFI only, so the
`ubuntu2204` nodeset points libvirt at the OVMF firmware. It uses
`/usr/share/OVMF/OVMF_CODE_4M.fd` (Debian/Ubuntu `ovmf` package) or
`/usr/share/edk2/ovmf/OVMF_CODE.fd` (Fedora `edk2-ovmf` package), whichever
exists; set `BEAKER_OVMF_CODE` to use another firmware file.

Please refer to the [SIMP Beaker Helpers documentation](https://github.com/simp/rubygem-simp-beaker-helpers/blob/master/README.md) for more information.

Some environment variables may be useful:

```shell
BEAKER_debug=true
BEAKER_provision=no
BEAKER_destroy=no
BEAKER_use_fixtures_dir_for_modules=yes
```

* `BEAKER_debug`: show the commands being run on the STU and their output.
* `BEAKER_destroy=no`: prevent the machine destruction after the tests finish so you can inspect the state.
* `BEAKER_provision=no`: prevent the machine from being recreated. This can save a lot of time while you're writing the tests.
* `BEAKER_use_fixtures_dir_for_modules=yes`: cause all module dependencies to be loaded from the `spec/fixtures/modules` directory, based on the contents of `.fixtures.yml`.  The contents of this directory are usually populated by `bundle exec rake spec_prep`.  This can be used to run acceptance tests to run on isolated networks.
