# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this module does

`pupmod-simp-ufw` is a SIMP Puppet module that manages the Uncomplicated
Firewall (ufw) on Ubuntu 22.04 and 24.04: the package, enabled state, default
policies, logging level, IPv6 support, service, and rules.

It deliberately **minimizes blast radius**: a bare `include ufw` installs the
`ufw` package and declares *nothing else*. Every other parameter is
`Optional` and defaults to `undef`, meaning "leave the system's value alone".
A later run that stops setting a parameter or a rule never reverts it; rules
are removed only with `ensure => absent`.

### Business logic

- **`manifests/init.pp`** (class `ufw`) — the only class.
  - `package_name`, `service_name`, `ufw_command`, `defaults_file`,
    `conf_file` come from module data (`hiera.yaml` + `data/common.yaml`).
    OS differences go in data (`data/os/<os.name>-<release.major>.yaml`),
    never in manifest conditionals.
  - `package_ensure` falls back to `simp_options::package_ensure`, then
    `installed`.
  - `enabled`, `default_*`, `logging` are `exec`s of the `ufw` command,
    guarded by `unless`/`onlyif` greps of `/etc/default/ufw` and
    `/etc/ufw/ufw.conf`, so they are idempotent and noop-safe (a missing
    file just makes the grep fail, and noop reports the exec).
  - `ipv6` is a `file_line` on `IPV6=` that notifies a refresh-only
    `ufw reload` (only when ufw is enabled).
  - `rules_entries` declares one `ufw_rule` per entry; `lookup_options`
    deep-merges it. `conflicting_packages_entries` manages other packages
    (removals happen before ufw is installed).
  - Order: package → IPv6 setting/reload → rules → default policies →
    logging → enable/disable → service.
  - Lockout guard: `enabled => true` with a non-`allow` incoming policy
    (unset counts as `deny`) fails compilation unless `ufw::allows_ssh()`
    (`functions/allows_ssh.pp`) finds an SSH rule in `rules_entries` or
    `allow_lockout` is `true`.
- **`types/`** — `Ufw::RuleOptions` (the `Struct` for rule entries, so typos
  fail at compile time), plus address/port/interface/comment aliases.
- **`lib/puppet/type/ufw_rule.rb`** / **`lib/puppet/provider/ufw_rule/ufw.rb`**
  — the custom type and its provider. **`lib/puppet_x/ufw/rule.rb`** holds the
  parsing, normalization and rendering logic.
  - State comes from the `### tuple ###` lines in `/etc/ufw/user.rules` and
    `user6.rules` (ufw's own rule store), not from running `ufw`. Reading the
    files has no side effects, works whether ufw is active or not, and
    yields nothing when ufw isn't installed.
  - Matching uses ufw's normalization (ufw 0.36 `common.py`/`util.py`):
    addresses, port order, application names; the comment is not part of a
    rule's identity. A rule without an address must exist in both address
    families (IPv6 only when `IPV6=yes`).
  - `optional_commands` (not `commands`), so the provider stays suitable on
    a node without ufw and `--noop` previews work. No side effects in
    `initialize`, `prefetch`, `instances` or getters.
  - `instances` names rules exactly as `ufw show added` prints them; the
    provider spec checks that against real captures.

## Dependencies

- `puppetlabs/stdlib` — `Stdlib::*` types and `file_line`.
- Runtime: `openvox >= 8.0.0 < 10.0.0` (see `metadata.json` `requirements`).

## Repository layout

- `manifests/init.pp`, `functions/`, `types/`, `lib/` — see above.
- `hiera.yaml` + `data/` — module data.
- `spec/classes/`, `spec/functions/`, `spec/unit/` — rspec-puppet and unit
  tests.
- `spec/data/ubuntu-{22.04,24.04}/` — `ufw show added` output and the rule
  files captured from the stock Ubuntu containers;
  `spec/data/create_rules.sh` re-creates the rules.
- `spec/support/facterdb_fallback.rb` — provides
  `on_supported_os_with_fallback`, which fills in FacterDB facts for the
  Ubuntu releases simp-rspec-puppet-facts 4.0.x lacks. Remove it once a
  simp-rspec-puppet-facts release with the FacterDB fallback
  (simp/rubygem-simp-rspec-puppet-facts#95) is out.
- `spec/acceptance/suites/default/` — beaker acceptance suite;
  `nodesets/ubuntu2204.yml` and `ubuntu2404.yml` (`default.yml` is 24.04).
- `REFERENCE.md` — generated Puppet Strings reference (do not hand-edit; regenerate).

## Common commands

This module uses `simp-rake-helpers` and `simp-beaker-helpers`; tasks come
from `Simp::Rake::Pupmod::Helpers` (see `Rakefile`).

```sh
bundle install

# Unit tests (rspec-puppet)
bundle exec rake spec

# Lint / style
bundle exec rake lint metadata_lint rubocop

# Regenerate REFERENCE.md after changing docstrings
bundle exec rake strings:generate:reference

# Acceptance tests (vagrant-libvirt, as in CI)
BEAKER_HYPERVISOR=vagrant_libvirt bundle exec rake beaker:suites[default,ubuntu2404]
BEAKER_HYPERVISOR=vagrant_libvirt bundle exec rake beaker:suites[default,ubuntu2204]
```

The `bento/ubuntu-22.04` libvirt box is UEFI-only and its box Vagrantfile
picks the `qemu` driver, so `nodesets/ubuntu2204.yml` passes
`libvirt: { driver: kvm, loader: ..., nvram: ... }` through beaker to
vagrant-libvirt. The loader is the first of
`/usr/share/OVMF/OVMF_CODE_4M.fd` (Ubuntu `ovmf`, used by CI) and
`/usr/share/edk2/ovmf/OVMF_CODE.fd` (Fedora `edk2-ovmf`) that exists; set
`BEAKER_OVMF_CODE` to override it. `vagrant destroy` leaves the NVRAM file
(`/var/lib/libvirt/qemu/nvram/beaker_ubuntu2204_VARS.fd`) behind; a later run
reuses it, or delete it by hand.

Note `.rspec` sets `--fail-fast`, so `rake spec` stops at the first failure.
Clean fixtures with `bundle exec rake fixtures:clean`.

## Conventions

- Follow the SIMP practices: every setting independently enforceable,
  three-state parameters, Hash `*_entries` parameters, noop-safety.
- In a container, ufw can add rules while inactive (it only updates its rule
  files), but it can't load them, and `ufw status` fails without
  `CAP_NET_ADMIN`; use a VM to test the running firewall.
- Keep manifest parameter `@param` docstrings current — `REFERENCE.md` is
  generated from them.
- Files marked `**This file is maintained with puppetsync**` are managed by
  the SIMP puppetsync baseline; do not hand-edit them here.
