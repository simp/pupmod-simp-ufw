# frozen_string_literal: true

require 'spec_helper'
require_relative '../support/facterdb_fallback'

describe 'ufw' do
  on_supported_os_with_fallback.each do |os, os_facts|
    context "on #{os}" do
      # Only base OS facts: this also proves the catalog compiles on a node
      # where ufw isn't installed yet.
      let(:facts) { os_facts }

      context 'with default parameters' do
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_package('ufw').with_ensure('installed') }

        it 'declares nothing but the package' do
          types = catalogue.resources.map(&:type).uniq - ['Class', 'Stage', 'Node']
          expect(types).to eq(['Package'])
          expect(catalogue.resources.count { |r| r.type == 'Package' }).to eq(1)
        end
      end

      context 'with simp_options::package_ensure set' do
        let(:hieradata) { 'package_ensure' }

        it { is_expected.to contain_package('ufw').with_ensure('latest') }

        context 'and package_ensure set' do
          let(:params) { { package_ensure: '0.36.2-6' } }

          it { is_expected.to contain_package('ufw').with_ensure('0.36.2-6') }
        end
      end

      context 'with the service managed' do
        let(:params) { { service_ensure: 'running', service_enable: true } }

        it { is_expected.to contain_service('ufw').with(ensure: 'running', enable: true).that_requires('Package[ufw]') }
        it { is_expected.not_to contain_exec('ufw-enable') }
      end

      context 'with only service_enable set' do
        let(:params) { { service_enable: false } }

        it { is_expected.to contain_service('ufw').with(enable: false).without_ensure }
      end

      context 'with enabled => false' do
        let(:params) { { enabled: false } }

        it do
          is_expected.to contain_exec('ufw-disable').with(
            command: '/usr/sbin/ufw disable',
            onlyif: "grep -qx 'ENABLED=yes' /etc/ufw/ufw.conf",
          )
        end
        it { is_expected.not_to contain_exec('ufw-enable') }
      end

      context 'with default policies and logging' do
        let(:params) do
          {
            default_incoming: 'deny',
            default_outgoing: 'reject',
            default_routed: 'allow',
            logging: 'medium',
          }
        end

        it do
          is_expected.to contain_exec('ufw-default-incoming').with(
            command: '/usr/sbin/ufw default deny incoming',
            unless: %(grep -Eqx 'DEFAULT_INPUT_POLICY="?DROP"?' /etc/default/ufw),
          ).that_requires('Package[ufw]')
        end
        it { is_expected.to contain_exec('ufw-default-outgoing').with_unless(%r{DEFAULT_OUTPUT_POLICY="\?REJECT"\?}) }
        it { is_expected.to contain_exec('ufw-default-routed').with_unless(%r{DEFAULT_FORWARD_POLICY="\?ACCEPT"\?}) }
        it { is_expected.to contain_exec('ufw-default-routed').that_comes_before('Exec[ufw-logging]') }
        it do
          is_expected.to contain_exec('ufw-logging').with(
            command: '/usr/sbin/ufw logging medium',
            unless: "grep -Eqx 'LOGLEVEL=medium' /etc/ufw/ufw.conf",
          )
        end
      end

      context 'with logging => on' do
        let(:params) { { logging: 'on' } }

        it { is_expected.to contain_exec('ufw-logging').with_unless("grep -Eqx 'LOGLEVEL=(low|medium|high|full)' /etc/ufw/ufw.conf") }
      end

      context 'with only default_outgoing set' do
        let(:params) { { default_outgoing: 'deny' } }

        it { is_expected.to contain_exec('ufw-default-outgoing') }
        it { is_expected.not_to contain_exec('ufw-default-incoming') }
        it { is_expected.not_to contain_exec('ufw-default-routed') }
      end

      [true, false].each do |value|
        context "with ipv6 => #{value}" do
          let(:params) { { ipv6: value } }
          let(:setting) { value ? 'yes' : 'no' }

          it do
            is_expected.to contain_file_line('ufw IPV6')
              .with(path: '/etc/default/ufw', line: "IPV6=#{setting}", match: '^IPV6=')
              .that_requires('Package[ufw]')
              .that_notifies('Exec[ufw-reload]')
          end
          it { is_expected.to contain_exec('ufw-reload').with(refreshonly: true, onlyif: "grep -qx 'ENABLED=yes' /etc/ufw/ufw.conf") }
        end
      end

      context 'with a full configuration' do
        let(:params) do
          {
            enabled: true,
            service_ensure: 'running',
            service_enable: true,
            default_incoming: 'deny',
            default_outgoing: 'deny',
            default_routed: 'deny',
            logging: 'low',
            ipv6: true,
            rules_entries: {
              'ssh' => { 'action' => 'allow', 'to_port' => 22, 'proto' => 'tcp' },
              'lo in' => { 'action' => 'allow', 'interface' => 'lo' },
              'old' => { 'ensure' => 'absent', 'action' => 'allow', 'to_port' => 23, 'proto' => 'tcp' },
            },
          }
        end

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_ufw_rule('ssh').with(to_port: 22, proto: 'tcp').that_requires('Package[ufw]') }
        it { is_expected.to contain_ufw_rule('old').with_ensure('absent') }
        it { is_expected.to contain_exec('ufw-reload').that_comes_before('Exec[ufw-default-incoming]') }

        ['ssh', 'lo in', 'old'].each do |rule|
          ['Exec[ufw-default-incoming]', 'Exec[ufw-default-outgoing]', 'Exec[ufw-default-routed]', 'Exec[ufw-logging]', 'Exec[ufw-enable]'].each do |exec|
            it { is_expected.to contain_ufw_rule(rule).that_comes_before(exec) }
          end
        end

        it { is_expected.to contain_exec('ufw-logging').that_comes_before('Exec[ufw-enable]') }
        it do
          is_expected.to contain_exec('ufw-enable').with(
            command: '/usr/sbin/ufw --force enable',
            unless: "grep -qx 'ENABLED=yes' /etc/ufw/ufw.conf",
          ).that_comes_before('Service[ufw]')
        end
      end

      context 'with conflicting_packages_entries' do
        let(:params) do
          {
            conflicting_packages_entries: {
              'iptables-persistent' => { 'ensure' => 'absent' },
              'netfilter-persistent' => {},
            },
          }
        end

        it { is_expected.to contain_package('iptables-persistent').with_ensure('absent').that_comes_before('Package[ufw]') }
        it { is_expected.to contain_package('netfilter-persistent').with_ensure('installed') }
      end

      context 'with a rule without an action' do
        let(:params) { { rules_entries: { 'everything' => {} } } }

        it { is_expected.to compile.and_raise_error(%r{needs an 'action' .* Missing in: everything}) }
      end

      context 'with a removal without an action' do
        let(:params) { { rules_entries: { 'old' => { 'ensure' => 'absent', 'to_port' => 23 } } } }

        it { is_expected.to compile.and_raise_error(%r{needs an 'action' .* Missing in: old}) }
      end

      context 'with an explicit rule allowing all incoming traffic' do
        let(:params) { { rules_entries: { 'everything' => { 'action' => 'allow' } } } }

        it { is_expected.to contain_ufw_rule('everything').with_action('allow') }
      end

      context 'with a typo in a rule' do
        let(:params) { { rules_entries: { 'ssh' => { 'action' => 'allow', 'to_prot' => 22 } } } }

        it { is_expected.to compile.and_raise_error(%r{unrecognized key 'to_prot'}) }
      end

      describe 'the lockout guard' do
        let(:base) { { enabled: true } }

        context 'with no rule allowing SSH' do
          let(:params) { base.merge(rules_entries: { 'web' => { 'action' => 'allow', 'to_port' => 443, 'proto' => 'tcp' } }) }

          it { is_expected.to compile.and_raise_error(%r{refusing to enable ufw with a 'deny' incoming policy}) }
        end

        context 'with default_incoming => reject and no rules' do
          let(:params) { base.merge(default_incoming: 'reject') }

          it { is_expected.to compile.and_raise_error(%r{'reject' incoming policy}) }
        end

        context 'with allow_lockout => true' do
          let(:params) { base.merge(allow_lockout: true) }

          it { is_expected.to compile.with_all_deps }
        end

        context 'with default_incoming => allow' do
          let(:params) { base.merge(default_incoming: 'allow') }

          it { is_expected.to compile.with_all_deps }
        end

        context 'with enabled => false' do
          let(:params) { { enabled: false, default_incoming: 'deny' } }

          it { is_expected.to compile.with_all_deps }
        end

        context 'with the OpenSSH app allowed' do
          let(:params) { base.merge(rules_entries: { 'ssh' => { 'action' => 'allow', 'to_app' => 'OpenSSH' } }) }

          it { is_expected.to compile.with_all_deps }
        end

        context 'with SSH on another port' do
          let(:rules) { { 'ssh' => { 'action' => 'allow', 'to_port' => '2200:2300', 'proto' => 'tcp' } } }

          context 'and the default lockout_guard_port' do
            let(:params) { base.merge(rules_entries: rules) }

            it { is_expected.to compile.and_raise_error(%r{port 22/tcp}) }
          end

          context 'and lockout_guard_port set' do
            let(:params) { base.merge(rules_entries: rules, lockout_guard_port: 2222) }

            it { is_expected.to compile.with_all_deps }
          end
        end

        context 'with the SSH rule being removed' do
          let(:params) { base.merge(rules_entries: { 'ssh' => { 'ensure' => 'absent', 'action' => 'allow', 'to_port' => 22, 'proto' => 'tcp' } }) }

          it { is_expected.to compile.and_raise_error(%r{refusing to enable ufw}) }
        end
      end
    end
  end
end
