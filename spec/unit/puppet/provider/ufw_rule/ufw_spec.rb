# frozen_string_literal: true

require 'spec_helper'

provider_class = Puppet::Type.type(:ufw_rule).provider(:ufw)
describe provider_class do
  let(:data_dir) { File.expand_path('../../../../data', __dir__) }

  def stub_files(rules: nil, rules6: nil, defaults: nil)
    allow(described_class).to receive(:read_file).with('/etc/ufw/user.rules').and_return(rules)
    allow(described_class).to receive(:read_file).with('/etc/ufw/user6.rules').and_return(rules6)
    allow(described_class).to receive(:read_file).with('/etc/default/ufw').and_return(defaults)
  end

  def provider_for(params)
    resource = Puppet::Type.type(:ufw_rule).new({ name: 'test' }.merge(params))
    described_class.prefetch('test' => resource)
    resource.provider
  end

  describe '.ipv6_enabled?' do
    it { expect(described_class.ipv6_enabled?(nil)).to be true }
    it { expect(described_class.ipv6_enabled?("IPV6=yes\n")).to be true }
    it { expect(described_class.ipv6_enabled?("IPV6=no\n")).to be false }
    it { expect(described_class.ipv6_enabled?(%(# IPV6=no\nIPV6="yes"\n))).to be true }
  end

  context 'when ufw is not installed' do
    before(:each) { stub_files }

    it 'finds no rules without running anything' do
      expect(described_class).not_to receive(:ufw)
      expect(described_class.instances).to be_empty
      expect(provider_for(to_port: 22, proto: 'tcp').exists?).to be false
    end
  end

  ['22.04', '24.04'].each do |release|
    context "with rules captured on Ubuntu #{release}" do
      let(:release_dir) { File.join(data_dir, "ubuntu-#{release}") }
      let(:show_added) do
        File.readlines(File.join(release_dir, 'show_added.txt'), chomp: true)
            .grep(%r{\Aufw }).map { |l| l.delete_prefix('ufw ') }
      end

      before(:each) do
        stub_files(
          rules: File.read(File.join(release_dir, 'user.rules')),
          rules6: File.read(File.join(release_dir, 'user6.rules')),
          defaults: "IPV6=yes\n",
        )
      end

      it 'names every rule exactly as `ufw show added` does, in the same order' do
        expect(described_class.instances.map(&:name)).to eq(show_added)
      end

      it 'reports comments' do
        rule = described_class.instances.find { |p| p.name.start_with?('allow out 443/tcp') }
        expect(rule.comment).to eq('https out')
      end

      it 'hides IPv6-only rules when IPv6 is disabled, like ufw' do
        allow(described_class).to receive(:read_file).with('/etc/default/ufw').and_return("IPV6=no\n")
        expect(described_class.instances.map(&:name)).not_to include('deny from ::1')
      end

      it 'turns each rule back into a resource that matches it' do
        described_class.instances.each do |instance|
          params = instance.instance_variable_get(:@property_hash).reject { |k, _| [:name, :ensure, :comment].include?(k) }
          provider = provider_for(params)
          # The `limit` rule only made it into user.rules (see spec/data/create_rules.sh)
          expect(provider.exists?).to be(!instance.name.start_with?('limit')), "#{instance.name}: #{params}"
        end
      end

      {
        'a port rule given as an Integer' => { to_port: 22, proto: 'tcp' },
        'loopback in' => { interface: 'lo' },
        'loopback out' => { interface: 'lo', direction: 'out' },
        'deny from 127.0.0.0/8' => { action: 'deny', from: '127.0.0.0/8' },
        'deny from ::1' => { action: 'deny', direction: 'in', from: '::1' },
        'an outbound rule without a protocol' => { direction: 'out', to_port: '53' },
        'ports in another order' => { from: '192.168.1.0/24', to: '192.168.1.5', to_port: ['8080:8090', 443, 80], proto: 'tcp' },
        'a network written with host bits' => { from: '10.1.2.3/8', proto: 'esp' },
        'a source port rule' => { from: '10.0.0.1', from_port: 123, proto: 'udp' },
        'an application rule' => { to_app: 'OpenSSH' },
        'an application rule with a space' => { from: '172.16.0.0/12', to_app: 'Web Full' },
        'an application rule on an interface' => { interface: 'eth0', to_app: 'OpenSSH' },
        'a source application rule' => { from: '10.1.0.0/16', to_app: 'OpenSSH' },
        'a logged rule' => { log: 'log', to_port: 2223, proto: 'tcp' },
        'a routed rule' => { route: true, interface: 'eth0', out_interface: 'eth1', to: '10.0.0.0/8', to_port: 80, proto: 'tcp' },
        'a routed rule leaving an interface' => { route: true, action: 'reject', direction: 'out', interface: 'eth3', from: '10.9.0.0/16' },
        'an IPv6 rule' => { action: 'reject', interface: 'eth0', from: '2001:DB8::/32', to_port: 25, proto: 'tcp' },
      }.each do |desc, params|
        it "recognizes #{desc}" do
          expect(provider_for(params).exists?).to be true
        end
      end

      {
        'a different action' => { action: 'deny', to_port: 22, proto: 'tcp' },
        'a different protocol' => { to_port: 22, proto: 'udp' },
        'a different direction' => { direction: 'out', to_port: 22, proto: 'tcp' },
        'a missing log type' => { to_port: 2223, proto: 'tcp' },
        'a different interface' => { interface: 'eth9' },
        'a routed form of an input rule' => { route: true, interface: 'lo' },
        'a different application' => { to_app: 'Web Full', interface: 'eth0' },
      }.each do |desc, params|
        it "does not match #{desc}" do
          expect(provider_for(params).exists?).to be false
        end
      end

      it 'needs a rule without addresses in both address families' do
        provider = provider_for(action: 'limit', to_port: 2222, proto: 'tcp')
        expect(provider.exists?).to be false
      end

      it 'removes a rule that remains in one address family' do
        provider = provider_for(ensure: 'absent', action: 'limit', to_port: 2222, proto: 'tcp')
        expect(provider.exists?).to be true
      end

      it 'needs a rule without addresses in IPv4 only when IPv6 is disabled' do
        allow(described_class).to receive(:read_file).with('/etc/default/ufw').and_return("IPV6=no\n")
        expect(provider_for(action: 'limit', to_port: 2222, proto: 'tcp').exists?).to be true
      end

      it 'reads the comment of a matched rule' do
        expect(provider_for(direction: 'out', interface: 'eth0', to: '8.8.8.8', to_port: 53, proto: 'udp').comment).to eq('say "dns"')
        expect(provider_for(to_port: 22, proto: 'tcp').comment).to eq('')
      end
    end
  end

  describe 'changes' do
    before(:each) { stub_files(defaults: "IPV6=yes\n") }

    it 'adds a rule with its comment' do
      provider = provider_for(to_port: 22, proto: 'tcp', comment: 'ssh')
      expect(provider).to receive(:ufw).with('allow', 'proto', 'tcp', 'from', 'any', 'to', 'any', 'port', '22', 'comment', 'ssh')
      provider.create
    end

    it 'adds a routed rule' do
      provider = provider_for(route: true, action: 'deny', interface: 'eth2')
      expect(provider).to receive(:ufw).with('route', 'deny', 'in', 'on', 'eth2', 'from', 'any', 'to', 'any')
      provider.create
    end

    it 'deletes a rule whatever its comment' do
      provider = provider_for(ensure: 'absent', direction: 'out', to_port: 53, comment: 'dns')
      expect(provider).to receive(:ufw).with('delete', 'allow', 'out', 'from', 'any', 'to', 'any', 'port', '53')
      provider.destroy
    end

    it 'updates a comment by adding the rule again' do
      provider = provider_for(to_port: 22, proto: 'tcp', comment: 'new')
      expect(provider).to receive(:ufw).with('allow', 'proto', 'tcp', 'from', 'any', 'to', 'any', 'port', '22', 'comment', 'new')
      provider.comment = 'new'
    end
  end
end
