# frozen_string_literal: true

require_relative '../../../puppet_x/ufw/rule'

Puppet::Type.type(:ufw_rule).provide(:ufw) do
  desc <<~DESC
    Manages ufw rules with the `ufw` command.

    The current rules are read from ufw's own rule store,
    `/etc/ufw/user.rules` and `/etc/ufw/user6.rules`, which ufw keeps up to
    date whether or not the firewall is active. Reading the files has no side
    effects and needs no `ufw` binary, so prefetching is safe under `--noop`
    and on a node where ufw isn't installed yet (it sees no rules).

    Rules are added with `ufw [route] <rule>` and removed with
    `ufw [route] delete <rule>`. Matching is done on ufw's normalized form of
    the rule, so a rule an administrator added by hand in any equivalent form
    is recognized. A rule that matches in everything but its action, log
    type or comment is replaced in place by ufw when the rule is added.
  DESC

  # Don't confine on the binary: a node where ufw isn't installed yet must
  # still be able to preview (`--noop`) the rules it would add.
  optional_commands ufw: 'ufw'

  confine kernel: 'Linux'
  defaultfor kernel: 'Linux'

  def self.read_file(path)
    File.read(path)
  rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR
    nil
  end

  # Whether ufw manages IPv6 (`IPV6=yes` in /etc/default/ufw). ufw ships with
  # IPv6 enabled, so that's assumed when the file is missing.
  def self.ipv6_enabled?(content = read_file(PuppetX::Ufw::Rule::DEFAULTS_FILE))
    return true if content.nil?

    setting = content.each_line.map { |l| l[%r{\AIPV6=(\S*)}, 1] }.compact.last
    setting.nil? || setting.delete('"\'').casecmp('yes').zero?
  end

  # The rules ufw knows about, and whether IPv6 is enabled.
  def self.rule_state
    {
      ipv6: ipv6_enabled?,
      rules: PuppetX::Ufw::Rule.parse_rules(read_file(PuppetX::Ufw::Rule::RULES_FILE), false) +
        PuppetX::Ufw::Rule.parse_rules(read_file(PuppetX::Ufw::Rule::RULES6_FILE), true),
    }
  end

  # Every rule, named after its `ufw show added` form.
  def self.instances
    state = rule_state
    rules = state[:rules].reject { |t| t[:v6] && !state[:ipv6] }

    rules.each_with_object({}) { |t, seen|
      name = PuppetX::Ufw::Rule.to_command(t)
      seen[name] ||= new(PuppetX::Ufw::Rule.to_options(t).merge(name: name, ensure: :present))
    }.values
  end

  # A resource without an `action` is one `puppet resource` built from a rule
  # name (`puppet resource ufw_rule 'allow 22/tcp' ensure=absent`). It gets
  # the provider of the existing rule with that name, if there is one.
  def self.prefetch(resources)
    state = rule_state
    existing = nil
    resources.each_value do |resource|
      if resource[:action].nil?
        existing ||= instances
        found = existing.find { |p| p.name == resource.name }
        resource.provider = new((found ? found.properties : { name: resource.name }).merge(state: state))
      else
        resource.provider = new(name: resource.name, state: state)
      end
    end
  end

  # What was read from the system for a provider built by `instances`
  def properties
    @property_hash.dup
  end

  # The rule's options: as declared, or for a resource without an `action`
  # (see `prefetch`), as read from the system.
  def rule_options
    source = (resource.nil? || resource[:action].nil?) ? @property_hash : resource
    opts = {}
    [:action, :route, :direction, :interface, :out_interface, :log, :proto,
     :from, :to, :from_port, :to_port, :from_app, :to_app].each do |param|
      opts[param] = source[param] unless source[param].nil?
    end
    opts
  end

  def state
    @property_hash[:state] ||= self.class.rule_state
  end

  # For each tuple the rule needs, the matching tuple on the system (or nil).
  def matches
    @matches ||= PuppetX::Ufw::Rule.desired_tuples(rule_options, state[:ipv6]).map do |want|
      state[:rules].find { |have| PuppetX::Ufw::Rule.match?(want, have) }
    end
  end

  # A rule to be present must exist in every address family it applies to.
  # A rule to be removed exists while it remains in any of them.
  def exists?
    return @property_hash[:ensure] == :present if resource[:action].nil?

    if resource[:ensure] == :absent
      matches.any?
    else
      !matches.empty? && matches.all?
    end
  end

  def run_ufw(args)
    ufw(*args)
  ensure
    @matches = nil
    @property_hash.delete(:state)
  end

  def create
    raise Puppet::Error, "ufw has no rule named '#{resource[:name]}', and adding one needs an 'action'" if rule_options[:action].nil?

    run_ufw(PuppetX::Ufw::Rule.command_args(rule_options.merge(comment: resource[:comment])))
  end

  def destroy
    run_ufw(PuppetX::Ufw::Rule.command_args(rule_options, delete: true))
  end

  def comment
    return @property_hash[:comment] if @property_hash.key?(:comment)

    comments = matches.compact.map { |t| t[:comment] }.uniq
    return :absent if comments.empty?

    # Report a family that differs from what's wanted, if there is one
    comments.find { |c| c != resource[:comment] } || comments.first
  end

  # ufw updates the comment of an existing rule in place when the rule is
  # added again with a different comment.
  def comment=(_value)
    create
  end
end
