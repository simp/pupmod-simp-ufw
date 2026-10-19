# frozen_string_literal: true

require 'puppet/parameter/boolean'
require_relative '../../puppet_x/ufw/rule'

Puppet::Type.newtype(:ufw_rule) do
  @doc = <<~DOC
    @summary Manages one ufw rule

    The title is a free-form name; the rule itself is described by the other
    parameters, which map onto ufw's extended rule syntax:

        ufw [route] ACTION [in|out [on INTERFACE]] [out on OUT_INTERFACE] [log|log-all]
            [proto PROTO] [from FROM [port FROM_PORT | app FROM_APP]]
            [to TO [port TO_PORT | app TO_APP]] [comment COMMENT]

    A rule is matched against ufw's rule store in ufw's normalized form, so
    an equivalent rule added by hand (for example `ufw allow ssh/tcp` for
    `to_port => 22, proto => 'tcp'`) is recognized; application names are
    matched ignoring case. A rule with no address (or `any`) applies to IPv4
    and, when ufw uses IPv6 (`IPV6=yes` in /etc/default/ufw and IPv6 support
    in the kernel), IPv6, and must exist in both to count as present.
    `0.0.0.0/0` is IPv4 only and `::/0` IPv6 only, as in ufw.

    Changing a rule's `action` or `log` adds a rule that differs from the
    existing one only in those, which ufw replaces in place.

    With `resources { 'ufw_rule': purge => true }`, a rule is purged only
    when no `ufw_rule` in the catalog that should be present describes it.

    @example Allow SSH from an admin network
      ufw_rule { 'ssh from admin net':
        action  => 'allow',
        from    => '10.0.0.0/8',
        to_port => 22,
        proto   => 'tcp',
        comment => 'SSH from the admin network',
      }

    @example Allow loopback traffic
      ufw_rule { 'allow in on lo':
        action    => 'allow',
        interface => 'lo',
      }
  DOC

  ensurable do
    desc 'Whether the rule should exist.'
    defaultvalues
    defaultto :present
  end

  newparam(:name, namevar: true) do
    desc 'A unique name for the rule. It is not passed to ufw.'
  end

  newparam(:action) do
    desc <<~DESC
      What to do with matching packets. Required, also for `ensure => absent`,
      since ufw only deletes a rule whose action matches.

      The exception is a resource with nothing but a name, or a name and
      `ensure => absent`, as `puppet resource` builds: it refers to the rule
      that `puppet resource ufw_rule` lists under that name. With
      `ensure => absent` that rule is removed if it exists; otherwise the
      resource is in sync when the rule exists and fails when it doesn't.
    DESC
    newvalues('allow', 'deny', 'reject', 'limit')
    munge(&:to_s)
  end

  newparam(:route, boolean: true, parent: Puppet::Parameter::Boolean) do
    desc 'Whether this is a routed (forwarded) rule (`ufw route ...`).'
    defaultto :false
  end

  newparam(:direction) do
    desc 'The direction of traffic the rule applies to.'
    newvalues('in', 'out')
    defaultto 'in'
    munge(&:to_s)
  end

  interface_validator = proc do |value|
    unless value.is_a?(String) && value =~ PuppetX::Ufw::Rule::INTERFACE_PATTERN && !['.', '..'].include?(value)
      raise ArgumentError, "Invalid interface name '#{value}'"
    end
  end

  newparam(:interface) do
    desc 'The interface (`on INTERFACE`) the rule applies to, in `direction`.'
    validate(&interface_validator)
  end

  newparam(:out_interface) do
    desc <<~DESC
      For a routed rule coming `in` on `interface`, the interface the traffic
      leaves on (`route ... in on INTERFACE out on OUT_INTERFACE`).
    DESC
    validate(&interface_validator)
  end

  newparam(:log) do
    desc 'Log new connections matching the rule (`log`), or all matching packets (`log-all`).'
    newvalues('log', 'log-all')
    munge(&:to_s)
  end

  newparam(:proto) do
    desc 'The protocol. `any` matches all protocols.'
    newvalues(*PuppetX::Ufw::Rule::PROTOCOLS)
    defaultto 'any'
    munge(&:to_s)
  end

  address_validator = proc do |value|
    next if value.to_s.casecmp('any').zero?

    begin
      IPAddr.new(value.to_s)
    rescue ArgumentError
      raise ArgumentError, "Invalid address '#{value}'"
    end
  end

  newparam(:from) do
    desc 'The source address or network, or `any`.'
    defaultto 'any'
    validate(&address_validator)
  end

  newparam(:to) do
    desc 'The destination address or network, or `any`.'
    defaultto 'any'
    validate(&address_validator)
  end

  port_validator = proc do |value|
    ports = Array(value).flat_map { |p| p.to_s.split(',') }
    raise ArgumentError, 'At least one port is required' if ports.empty?

    ports.each do |port|
      raise ArgumentError, "Invalid port '#{port}'" unless PuppetX::Ufw::Rule::PORT_PATTERN.match?(port)

      range = port.split(':').map(&:to_i)
      raise ArgumentError, "Invalid port '#{port}'" unless range.all? { |p| p.between?(1, 65_535) }
      raise ArgumentError, "Invalid port range '#{port}'" if range.length == 2 && range[0] >= range[1]
    end
    # iptables' multiport match takes at most 15 ports
    raise ArgumentError, 'Too many ports (iptables allows at most 15)' if ports.join(',').count(',:') > 14
  end

  newparam(:from_port) do
    desc 'The source port: a port, a range (`8000:8100`), or a list of them (Array or comma-separated).'
    validate(&port_validator)
    munge { |value| PuppetX::Ufw::Rule.normalize_ports(value) }
  end

  newparam(:to_port) do
    desc 'The destination port: a port, a range (`8000:8100`), or a list of them (Array or comma-separated).'
    validate(&port_validator)
    munge { |value| PuppetX::Ufw::Rule.normalize_ports(value) }
  end

  app_validator = proc do |value|
    raise ArgumentError, "Invalid application profile name '#{value}'" unless value.is_a?(String) && value =~ %r{\A[^'"\n\r/]+\z}
  end

  newparam(:from_app) do
    desc 'A ufw application profile (`ufw app list`) for the source ports.'
    validate(&app_validator)
  end

  newparam(:to_app) do
    desc 'A ufw application profile (`ufw app list`) for the destination ports, e.g. `OpenSSH`.'
    validate(&app_validator)
  end

  newproperty(:comment) do
    desc <<~DESC
      A comment stored with the rule. ufw doesn't allow `'` in comments.
      When unset, any existing comment is left alone.
    DESC

    validate do |value|
      raise ArgumentError, "A ufw comment may not contain \"'\" or line breaks" unless value.is_a?(String) && value !~ %r{['\n\r]}
    end
  end

  validate do
    # `puppet resource ufw_rule [NAME]` looks rules up by name, and
    # `puppet resource ufw_rule NAME ensure=absent` removes the rule with that
    # name. The provider takes those rules' options from the system, and
    # refuses to add a rule without an action.
    given = original_parameters.keys - [:name, :provider, :audit]
    next if given.empty? || (given == [:ensure] && self[:ensure] == :absent)

    raise ArgumentError, "ufw_rule[#{self[:name]}]: 'action' is required (allow, deny, reject or limit)" if self[:action].nil?

    route = [true, :true].include?(self[:route])
    proto = self[:proto].to_s
    has_app = self[:from_app] || self[:to_app]
    has_port = self[:from_port] || self[:to_port]

    raise ArgumentError, "A rule can't have both 'from_port' and 'from_app'" if self[:from_port] && self[:from_app]
    raise ArgumentError, "A rule can't have both 'to_port' and 'to_app'" if self[:to_port] && self[:to_app]
    raise ArgumentError, "Application rules can't set 'proto'" if has_app && proto != 'any'
    raise ArgumentError, "Protocol '#{proto}' doesn't use ports" if has_port && PuppetX::Ufw::Rule::PORTLESS_PROTOCOLS.include?(proto)

    multi = [self[:from_port], self[:to_port]].compact.any? { |p| p.include?(',') || p.include?(':') }
    raise ArgumentError, "Port lists and ranges need 'proto' set to 'tcp' or 'udp'" if multi && !['tcp', 'udp'].include?(proto)

    from_v6 = PuppetX::Ufw::Rule.v6_address?(self[:from])
    to_v6 = PuppetX::Ufw::Rule.v6_address?(self[:to])
    if !self[:from].to_s.casecmp('any').zero? && !self[:to].to_s.casecmp('any').zero? && from_v6 != to_v6
      raise ArgumentError, "'from' and 'to' must be in the same address family"
    end
    if (from_v6 || to_v6) && PuppetX::Ufw::Rule::IPV4_ONLY_PROTOCOLS.include?(proto)
      raise ArgumentError, "Protocol '#{proto}' can't be used with IPv6 addresses"
    end

    if self[:out_interface]
      unless route && self[:interface] && self[:direction].to_s == 'in'
        raise ArgumentError, "'out_interface' needs 'route' => true, 'direction' => 'in' and 'interface'"
      end
    end
    raise ArgumentError, "A routed rule with 'direction' => 'out' needs 'interface'" if route && self[:direction].to_s == 'out' && !self[:interface]
  end

  autorequire(:package) { ['ufw'] }

  # Apply IPv6 setting changes before rules, and rules before the default
  # policies and before ufw is enabled (see class ufw).
  autorequire(:exec) { ['ufw-reload'] }
  autobefore(:exec) { ['ufw-default-incoming', 'ufw-default-outgoing', 'ufw-default-routed', 'ufw-enable'] }
end
