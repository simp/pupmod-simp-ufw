# frozen_string_literal: true

require 'ipaddr'

module PuppetX # rubocop:disable Style/ClassAndModuleChildren
  module Ufw
    # Parsing, normalization and rendering of ufw rules.
    #
    # ufw keeps its rules in /etc/ufw/user.rules (IPv4) and
    # /etc/ufw/user6.rules (IPv6). Each rule is recorded there as a
    # `### tuple ###` comment, which is what ufw itself reads back to rebuild
    # its rule list, so it is the authoritative and most structured record of
    # the rules ufw has been told about. The tuple fields are:
    #
    #   [route:]action[_logtype] proto dport dst sport src [dapp sapp] dir [comment=<hex>]
    #
    # where `dir` is `in`, `out`, `in_<iface>`, `out_<iface>` or
    # `in_<iface>!out_<iface>`.
    #
    # The normalization rules below follow ufw's own (ufw/common.py and
    # ufw/util.py in ufw 0.36), so that a rule given to ufw in any
    # equivalent form is matched against what ufw wrote.
    module Rule
      # ufw's rule store and settings. These paths are compiled into ufw.
      RULES_FILE = '/etc/ufw/user.rules'
      RULES6_FILE = '/etc/ufw/user6.rules'
      DEFAULTS_FILE = '/etc/default/ufw'

      ANY4 = '0.0.0.0/0'
      ANY6 = '::/0'

      PROTOCOLS = ['any', 'tcp', 'udp', 'ipv6', 'esp', 'ah', 'igmp', 'gre', 'vrrp'].freeze
      PORTLESS_PROTOCOLS = ['ipv6', 'esp', 'ah', 'igmp', 'gre', 'vrrp'].freeze
      IPV4_ONLY_PROTOCOLS = ['ipv6', 'igmp'].freeze

      INTERFACE_PATTERN = %r{\A[a-zA-Z0-9_\-.+,=%@]{1,15}\z}.freeze
      PORT_PATTERN = %r{\A\d+(:\d+)?\z}.freeze

      # The fields that identify a rule within one address family. A rule
      # differing only in its comment is the same rule (ufw updates the
      # comment in place).
      IDENTITY = [:forward, :action, :logtype, :proto, :dport, :dst, :sport, :src,
                  :dapp, :sapp, :interface_in, :interface_out, :direction].freeze

      module_function

      # Parse the `### tuple ###` lines of a ufw rules file.
      #
      # @param content [String] the content of user.rules or user6.rules
      # @param v6 [Boolean] whether the content came from user6.rules
      # @return [Array<Hash>] one Hash per tuple
      def parse_rules(content, v6)
        content.to_s.each_line.map { |line| parse_tuple(line, v6) }.compact
      end

      # Parse one `### tuple ###` line.
      #
      # @return [Hash, nil] nil if the line isn't a well-formed tuple
      def parse_tuple(line, v6)
        return nil unless line.chomp =~ %r{\A### tuple ###\s*(.*)\z}

        tuple = Regexp.last_match(1).strip
        comment = ''
        if tuple.include?(' comment=')
          tuple, hex = tuple.split(' comment=', 2)
          comment = hex_decode(hex.strip)
        end

        fields = tuple.split(%r{\s+})
        return nil unless [7, 9].include?(fields.length)

        action = fields[0]
        forward = false
        if action.include?(':')
          forward = true
          action = action.split(':', 2)[1]
        end
        action, logtype = action.split('_', 2)

        dir = fields[-1]
        direction = dir.split('_', 2)[0]
        interface_in = ''
        interface_out = ''
        if dir.include?('!')
          interface_in = dir.split('!', 2)[0].partition('_')[2]
          interface_out = dir.split('!', 2)[1].partition('_')[2]
        elsif dir.start_with?('in_')
          interface_in = dir.partition('_')[2]
        elsif dir.start_with?('out_')
          interface_out = dir.partition('_')[2]
        end

        dapp = ''
        sapp = ''
        if fields.length == 9
          dapp = (fields[6] == '-') ? '' : fields[6].gsub('%20', ' ')
          sapp = (fields[7] == '-') ? '' : fields[7].gsub('%20', ' ')
        end

        {
          v6: v6,
          forward: forward,
          action: action,
          logtype: logtype.to_s,
          proto: fields[1],
          dport: fields[2],
          dst: fields[3],
          sport: fields[4],
          src: fields[5],
          dapp: dapp,
          sapp: sapp,
          interface_in: interface_in,
          interface_out: interface_out,
          direction: direction,
          comment: comment,
        }
      end

      def hex_decode(hex)
        [hex].pack('H*').force_encoding('UTF-8')
      end

      # Whether an address (as a rule option) is IPv6.
      def v6_address?(addr)
        !addr.nil? && addr.to_s.include?(':')
      end

      # Normalize an address the way ufw does: `any` becomes the family's
      # wildcard network, host netmasks are dropped, IPv4 dotted netmasks
      # become CIDR prefixes, IPv4 networks are reduced to their network
      # address, and the address itself is put in canonical form.
      def normalize_address(addr, v6)
        addr = addr.to_s.downcase
        return (v6 ? ANY6 : ANY4) if ['any', '', ANY4, ANY6].include?(addr)

        host, mask = addr.split('/', 2)
        mask = nil if v6 && mask == '128'
        mask = nil if !v6 && ['32', '255.255.255.255'].include?(mask)
        if !v6 && mask&.include?('.')
          bits = IPAddr.new(mask).to_i.to_s(2)
          mask = bits.count('1').to_s if %r{\A1*0*\z}.match?(bits)
        end

        host = IPAddr.new(host).to_s
        return host unless mask

        host = IPAddr.new("#{host}/#{mask}").to_s unless v6
        "#{host}/#{mask}"
      end

      # Normalize a port specification (Integer, String or Array) to the
      # comma-separated, naturally sorted String ufw stores.
      #
      # @return [String, nil] nil when no ports are given
      def normalize_ports(ports)
        return nil if ports.nil? || ports == '' || ports == 'any'

        list = Array(ports).flat_map { |p| p.to_s.split(',') }.map(&:strip)
        list.sort_by { |p| p.split(%r{(\d+)}).map { |c| %r{\A\d+\z}.match?(c) ? c.to_i : c.downcase } }.join(',')
      end

      # The address families a rule applies to.
      #
      # @param opts [Hash] rule options (symbol keys, as from the type)
      # @param ipv6_enabled [Boolean] whether IPV6=yes in /etc/default/ufw
      def families(opts, ipv6_enabled)
        if v6_address?(opts[:from]) || v6_address?(opts[:to])
          [true]
        elsif [opts[:from], opts[:to]].any? { |a| !a.nil? && !['any', ANY4, ANY6].include?(a.to_s.downcase) }
          [false]
        elsif IPV4_ONLY_PROTOCOLS.include?(opts[:proto].to_s) || !ipv6_enabled
          [false]
        else
          [false, true]
        end
      end

      # Build the tuples (without comments) that ufw would record for a rule.
      #
      # @param opts [Hash] rule options: :action, :route, :direction,
      #   :interface, :out_interface, :log, :proto, :from, :to, :from_port,
      #   :to_port, :from_app, :to_app
      # @return [Array<Hash>]
      def desired_tuples(opts, ipv6_enabled)
        direction = (opts[:direction] || 'in').to_s
        interface_in = ''
        interface_out = ''
        if opts[:interface]
          if direction == 'out'
            interface_out = opts[:interface].to_s
          else
            interface_in = opts[:interface].to_s
          end
        end
        interface_out = opts[:out_interface].to_s if opts[:out_interface]

        families(opts, ipv6_enabled).map do |v6|
          {
            v6: v6,
            forward: [true, :true, 'true'].include?(opts[:route]),
            action: (opts[:action] || 'allow').to_s,
            logtype: opts[:log].to_s,
            proto: (opts[:proto] || 'any').to_s,
            dport: normalize_ports(opts[:to_port]) || 'any',
            dst: normalize_address(opts[:to] || 'any', v6),
            sport: normalize_ports(opts[:from_port]) || 'any',
            src: normalize_address(opts[:from] || 'any', v6),
            dapp: opts[:to_app].to_s,
            sapp: opts[:from_app].to_s,
            interface_in: interface_in,
            interface_out: interface_out,
            direction: direction,
          }
        end
      end

      # Whether two tuples describe the same rule (ignoring the comment).
      #
      # For application rules, ufw fills in the protocol and ports from the
      # application profile, so those are compared by application name only.
      def match?(a, b)
        IDENTITY.all? do |field|
          next true if field == :proto && (!a[:dapp].empty? || !a[:sapp].empty?)
          next true if field == :dport && !a[:dapp].empty?
          next true if field == :sport && !a[:sapp].empty?

          a[field] == b[field]
        end && a[:v6] == b[:v6]
      end

      # The ufw command-line arguments for a rule, as accepted by
      # `ufw [route] [delete] ...`, always in ufw's extended syntax.
      #
      # @param opts [Hash] rule options as for #desired_tuples
      # @param delete [Boolean] build a `delete` command (without the comment,
      #   so that ufw deletes the rule whatever its comment is)
      # @return [Array<String>]
      def command_args(opts, delete: false)
        args = []
        args << 'route' if [true, :true, 'true'].include?(opts[:route])
        args << 'delete' if delete
        args << (opts[:action] || 'allow').to_s

        direction = (opts[:direction] || 'in').to_s
        if opts[:interface]
          args += [direction, 'on', opts[:interface].to_s]
        elsif direction == 'out'
          args << 'out'
        end
        args += ['out', 'on', opts[:out_interface].to_s] if opts[:out_interface]

        args << opts[:log].to_s if opts[:log]

        proto = (opts[:proto] || 'any').to_s
        args += ['proto', proto] unless proto == 'any'

        args += ['from', (opts[:from] || 'any').to_s]
        if opts[:from_app]
          args += ['app', opts[:from_app].to_s]
        elsif (ports = normalize_ports(opts[:from_port]))
          args += ['port', ports]
        end

        args += ['to', (opts[:to] || 'any').to_s]
        if opts[:to_app]
          args += ['app', opts[:to_app].to_s]
        elsif (ports = normalize_ports(opts[:to_port]))
          args += ['port', ports]
        end

        args += ['comment', opts[:comment].to_s] if !delete && !opts[:comment].nil?
        args
      end

      def anywhere?(addr)
        [ANY4, ANY6].include?(addr)
      end

      def quote_app(app)
        app.include?(' ') ? "'#{app}'" : app
      end

      # Render a tuple the way `ufw show added` does (ufw's get_command),
      # without the leading `ufw `.
      def to_command(t)
        res = t[:action].dup

        if anywhere?(t[:dst]) && anywhere?(t[:src]) && t[:sport] == 'any' && t[:sapp].empty? &&
           t[:interface_in].empty? && t[:interface_out].empty? && t[:dport] != 'any'
          # Short syntax
          res << " #{t[:direction]}" if t[:direction] == 'out'
          res << " #{t[:logtype]}" unless t[:logtype].empty?
          if t[:dapp].empty?
            res << " #{t[:dport]}"
            res << "/#{t[:proto]}" unless t[:proto] == 'any'
          else
            res << " #{quote_app(t[:dapp])}"
          end
        else
          # Extended syntax
          res << " in on #{t[:interface_in]}" unless t[:interface_in].empty?
          if !t[:interface_out].empty?
            res << " out on #{t[:interface_out]}"
          elsif t[:direction] == 'out'
            res << ' out'
          end
          res << " #{t[:logtype]}" unless t[:logtype].empty?

          [[:src, :sport, :sapp, 'from'], [:dst, :dport, :dapp, 'to']].each do |loc_key, port_key, app_key, word|
            loc = anywhere?(t[loc_key]) ? 'any' : t[loc_key]
            port = t[port_key]
            app = t[app_key]
            next unless loc != 'any' || port != 'any' || !app.empty?

            res << " #{word} #{loc}"
            if !app.empty?
              res << " app #{quote_app(app)}"
            elsif port != 'any'
              res << " port #{port}"
            end
          end

          res << ' to any' if !res.include?(' to ') && !res.include?(' from ') && t[:interface_in].empty? && t[:interface_out].empty?
          res << " proto #{t[:proto]}" if t[:proto] != 'any' && t[:dapp].empty? && t[:sapp].empty?
        end

        res << " comment '#{t[:comment]}'" unless t[:comment].to_s.empty?
        t[:forward] ? "route #{res}" : res
      end

      # Convert a tuple to rule options, as used by `puppet resource`.
      def to_options(t)
        opts = { action: t[:action] }
        opts[:route] = :true if t[:forward]
        opts[:direction] = t[:direction]
        if !t[:interface_in].empty?
          opts[:interface] = t[:interface_in]
          opts[:out_interface] = t[:interface_out] unless t[:interface_out].empty?
        elsif !t[:interface_out].empty?
          opts[:interface] = t[:interface_out]
        end
        opts[:log] = t[:logtype] unless t[:logtype].empty?
        opts[:proto] = t[:proto] if t[:dapp].empty? && t[:sapp].empty?
        opts[:from] = anywhere?(t[:src]) ? 'any' : t[:src]
        opts[:to] = anywhere?(t[:dst]) ? 'any' : t[:dst]
        if t[:sapp].empty?
          opts[:from_port] = t[:sport] unless t[:sport] == 'any'
        else
          opts[:from_app] = t[:sapp]
        end
        if t[:dapp].empty?
          opts[:to_port] = t[:dport] unless t[:dport] == 'any'
        else
          opts[:to_app] = t[:dapp]
        end
        opts[:comment] = t[:comment]
        opts
      end
    end
  end
end
