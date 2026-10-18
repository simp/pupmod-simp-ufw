require 'spec_helper_acceptance'

test_name 'ufw class'

# Render a class declaration. Ruby's Hash#inspect output is valid Puppet
# hash syntax for the String/Integer/Boolean values used here.
def ufw_manifest(params)
  "class { 'ufw': #{params.map { |k, v| "#{k} => #{v.inspect}" }.join(', ')} }"
end

# A CIS-style configuration: SSH allowed first, loopback traffic allowed and
# spoofed loopback traffic denied, a few outbound services, default deny in
# every direction, logging, and ufw enabled with its service.
FULL_PARAMS = {
  'enabled' => true,
  'service_ensure' => 'running',
  'service_enable' => true,
  'default_incoming' => 'deny',
  'default_outgoing' => 'deny',
  'default_routed' => 'deny',
  'logging' => 'low',
  'ipv6' => true,
  'rules_entries' => {
    'ssh' => { 'to_port' => 22, 'proto' => 'tcp' },
    'loopback in' => { 'interface' => 'lo' },
    'loopback out' => { 'interface' => 'lo', 'direction' => 'out' },
    'deny spoofed loopback v4' => { 'action' => 'deny', 'from' => '127.0.0.0/8' },
    'deny spoofed loopback v6' => { 'action' => 'deny', 'from' => '::1' },
    'dns out' => { 'direction' => 'out', 'to_port' => 53 },
    'web out' => { 'direction' => 'out', 'to_port' => [80, 443], 'proto' => 'tcp' },
    'ntp out' => { 'direction' => 'out', 'to_port' => 123, 'proto' => 'udp' },
  },
}.freeze

def full_manifest(extra_rules = {})
  ufw_manifest(FULL_PARAMS.merge('rules_entries' => FULL_PARAMS['rules_entries'].merge(extra_rules)))
end

describe 'ufw class' do
  hosts.each do |host|
    context "on #{host}" do
      let(:show_added) { on(host, 'ufw show added').stdout }

      context 'in noop mode with the full configuration on a node without ufw' do
        # Staging, not an assertion: the module must cope with ufw missing
        before(:context) do
          on(host, 'DEBIAN_FRONTEND=noninteractive apt-get purge -y ufw')
        end

        it 'previews the changes without errors' do
          result = apply_manifest_on(host, full_manifest, noop: true, catch_failures: true)
          expect(result.stderr).not_to include('Error:')
          [
            %r{Package\[ufw\]/ensure: created \(noop\)},
            %r{File_line\[ufw IPV6\]/ensure: created \(noop\)},
            %r{Ufw_rule\[ssh\]/ensure: created \(noop\)},
            %r{Ufw_rule\[dns out\]/ensure: created \(noop\)},
            %r{Exec\[ufw-default-incoming\]/returns: executed successfully \(noop\)},
            %r{Exec\[ufw-logging\]/returns: executed successfully \(noop\)},
            %r{Exec\[ufw-enable\]/returns: executed successfully \(noop\)},
            %r{Service\[ufw\]/enable: enable changed 'false' to 'true' \(noop\)},
          ].each do |change|
            expect(result.stdout).to match(change)
          end
        end

        it 'leaves ufw uninstalled' do
          result = on(host, "dpkg-query -W -f '${Status}' ufw", acceptable_exit_codes: [0, 1])
          expect(result.stdout).not_to include('install ok installed')
        end
      end

      context 'with default parameters' do
        let(:manifest) { 'include ufw' }

        it 'applies without errors' do
          result = apply_manifest_on(host, manifest, catch_failures: true)
          changed = result.stdout.scan(%r{/Stage\[main\]/Ufw/(\w+)\[}).flatten.uniq
          expect(changed).to eq(['Package'])
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, catch_changes: true)
        end

        it 'installs ufw and leaves it inactive' do
          on(host, 'dpkg-query -W ufw')
          expect(on(host, 'ufw status').stdout).to match(%r{^Status: inactive})
        end

        it 'leaves settings changed by hand alone' do
          on(host, 'ufw logging medium')
          on(host, 'ufw allow 8000/tcp')
          apply_manifest_on(host, manifest, catch_changes: true)
          expect(on(host, 'grep ^LOGLEVEL= /etc/ufw/ufw.conf').stdout.strip).to eq('LOGLEVEL=medium')
          expect(show_added).to include('ufw allow 8000/tcp')
          on(host, 'ufw delete allow 8000/tcp')
        end
      end

      context 'when enabling ufw with no rule allowing SSH' do
        it 'fails to compile' do
          manifest = ufw_manifest('enabled' => true, 'rules_entries' => { 'web' => { 'to_port' => 443, 'proto' => 'tcp' } })
          result = apply_manifest_on(host, manifest, expect_failures: true)
          expect(result.stderr).to include("refusing to enable ufw with a 'deny' incoming policy")
        end

        it 'changes nothing' do
          expect(on(host, 'ufw status').stdout).to match(%r{^Status: inactive})
          expect(show_added).not_to include('443')
        end
      end

      context 'with the full configuration' do
        it 'applies without errors' do
          apply_manifest_on(host, full_manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, full_manifest, catch_changes: true)
        end

        it 'enables ufw with the default policies and logging' do
          status = on(host, 'ufw status verbose').stdout
          expect(status).to match(%r{^Status: active})
          expect(status).to match(%r{^Logging: on \(low\)})
          # ufw reports the routed policy as `disabled` while the kernel
          # doesn't forward packets, whatever the configured policy is
          expect(status).to match(%r{^Default: deny \(incoming\), deny \(outgoing\), (deny|disabled) \(routed\)})
          expect(on(host, 'grep ^DEFAULT_FORWARD_POLICY= /etc/default/ufw').stdout.strip).to eq('DEFAULT_FORWARD_POLICY="DROP"')
        end

        it 'adds the rules' do
          [
            'ufw allow 22/tcp',
            'ufw allow in on lo',
            'ufw allow out on lo',
            'ufw deny from 127.0.0.0/8',
            'ufw deny from ::1',
            'ufw allow out 53',
            'ufw allow out 80,443/tcp',
            'ufw allow out 123/udp',
          ].each do |rule|
            expect(show_added.lines.map(&:strip)).to include(rule)
          end
        end

        it 'loads the rules into the running firewall' do
          expect(on(host, 'iptables -S ufw-user-input').stdout).to match(%r{-p tcp .*--dport 22 -j ACCEPT})
          expect(on(host, 'ip6tables -S ufw6-user-input').stdout).to match(%r{-p tcp .*--dport 22 -j ACCEPT})
        end

        it 'enables and starts the service' do
          on(host, 'systemctl is-enabled ufw')
          on(host, 'systemctl is-active ufw')
        end

        it 'leaves SSH reachable' do
          host.close
          on(host, 'true')
        end
      end

      context 'with a rule an administrator added by hand' do
        before(:context) { on(host, 'ufw allow 8443/tcp') }

        it 'recognizes the equivalent rule' do
          apply_manifest_on(host, full_manifest('alt https' => { 'to_port' => '8443', 'proto' => 'tcp' }), catch_changes: true)
        end

        it 'removes it with ensure => absent' do
          apply_manifest_on(host, full_manifest('alt https' => { 'ensure' => 'absent', 'to_port' => 8443, 'proto' => 'tcp' }), catch_failures: true)
          expect(show_added).not_to include('8443')
        end
      end

      context 'with one rule set, then unset, then absent' do
        let(:rule) { { 'action' => 'allow', 'from' => '10.0.0.0/8', 'to_port' => 5432, 'proto' => 'tcp', 'comment' => 'database' } }
        let(:listed) { "ufw allow from 10.0.0.0/8 to any port 5432 proto tcp comment 'database'" }

        it 'adds the rule when it is set' do
          apply_manifest_on(host, full_manifest('database' => rule), catch_failures: true)
          apply_manifest_on(host, full_manifest('database' => rule), catch_changes: true)
          expect(show_added.lines.map(&:strip)).to include(listed)
        end

        it 'updates its comment in place' do
          apply_manifest_on(host, full_manifest('database' => rule.merge('comment' => 'postgres')), catch_failures: true)
          apply_manifest_on(host, full_manifest('database' => rule.merge('comment' => 'postgres')), catch_changes: true)
          expect(show_added.lines.map(&:strip)).to include(listed.sub('database', 'postgres'))
          apply_manifest_on(host, full_manifest('database' => rule), catch_failures: true)
        end

        it 'leaves the rule alone when it is unset' do
          apply_manifest_on(host, full_manifest, catch_changes: true)
          expect(show_added.lines.map(&:strip)).to include(listed)
        end

        it 'removes the rule when it is absent' do
          apply_manifest_on(host, full_manifest('database' => rule.merge('ensure' => 'absent')), catch_failures: true)
          apply_manifest_on(host, full_manifest('database' => rule.merge('ensure' => 'absent')), catch_changes: true)
          expect(show_added).not_to include('5432')
        end
      end

      context 'with a routed rule and an application rule' do
        let(:rules) do
          {
            'routed' => { 'route' => true, 'interface' => 'lo', 'out_interface' => 'lo', 'to' => '10.0.0.0/8', 'to_port' => 80, 'proto' => 'tcp' },
            'openssh' => { 'from' => '192.168.0.0/16', 'to_app' => 'OpenSSH', 'log' => 'log' },
          }
        end

        it 'adds them idempotently' do
          apply_manifest_on(host, full_manifest(rules), catch_failures: true)
          apply_manifest_on(host, full_manifest(rules), catch_changes: true)
          expect(show_added.lines.map(&:strip)).to include('ufw route allow in on lo out on lo to 10.0.0.0/8 port 80 proto tcp')
          expect(show_added.lines.map(&:strip)).to include('ufw allow log from 192.168.0.0/16 to any app OpenSSH')
        end
      end
    end
  end
end
