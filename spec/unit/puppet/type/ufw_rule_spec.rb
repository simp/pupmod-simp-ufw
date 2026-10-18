# frozen_string_literal: true

require 'spec_helper'

describe Puppet::Type.type(:ufw_rule) do
  def rule(params)
    described_class.new({ name: 'test', action: 'allow' }.merge(params))
  end

  it 'requires an action' do
    expect { described_class.new(name: 'test') }.to raise_error(Puppet::ResourceError, %r{'action' is required})
    expect { described_class.new(name: 'test', ensure: 'absent', to_port: 22) }.to raise_error(Puppet::ResourceError, %r{'action' is required})
  end

  it 'defaults to a rule for incoming traffic' do
    r = rule({})
    expect(r[:ensure]).to eq(:present)
    expect(r[:direction]).to eq('in')
    expect(r[:proto]).to eq('any')
    expect(r[:from]).to eq('any')
    expect(r[:route]).to be false
  end

  it 'normalizes ports' do
    expect(rule(to_port: [443, '80'], proto: 'tcp')[:to_port]).to eq('80,443')
    expect(rule(to_port: 22)[:to_port]).to eq('22')
  end

  it 'accepts a full rule' do
    expect {
      rule(route: true, action: 'limit', interface: 'eth0', out_interface: 'eth1', log: 'log-all',
           proto: 'udp', from: '10.0.0.0/8', from_port: '1000:2000', to: '192.168.0.1', to_port: '53,5353', comment: 'say "hi"')
    }.not_to raise_error
  end

  {
    'an unknown action' => { action: 'drop' },
    'a bad interface' => { interface: 'eth0:1' },
    'a long interface' => { interface: 'a' * 16 },
    'a bad address' => { from: '10.0.0.300' },
    'a bad port' => { to_port: 70_000 },
    'a reversed port range' => { to_port: '200:100', proto: 'tcp' },
    'too many ports' => { to_port: (1..16).to_a, proto: 'tcp' },
    'a comment with a quote' => { comment: "it's" },
    'a port and an app on one side' => { to_port: 22, to_app: 'OpenSSH' },
    'an app with a protocol' => { to_app: 'OpenSSH', proto: 'tcp' },
    'ports with a portless protocol' => { to_port: 22, proto: 'esp' },
    'a port range without tcp or udp' => { to_port: '1000:2000' },
    'a port list without tcp or udp' => { to_port: [80, 443] },
    'mixed address families' => { from: '10.0.0.1', to: '::1' },
    'an IPv4-only protocol with an IPv6 address' => { from: '::1', proto: 'igmp' },
    'out_interface on an input rule' => { interface: 'eth0', out_interface: 'eth1' },
    'out_interface without interface' => { route: true, out_interface: 'eth1' },
    'an outgoing routed rule without an interface' => { route: true, direction: 'out' },
  }.each do |desc, params|
    it "rejects #{desc}" do
      expect { rule(params) }.to raise_error(Puppet::ResourceError)
    end
  end

  it 'builds resources from the existing rules for `puppet resource`' do
    provider = described_class.provider(:ufw)
    allow(provider).to receive(:read_file).and_return(nil)
    allow(provider).to receive(:read_file).with('/etc/ufw/user.rules').and_return("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n")
    expect(described_class.instances.map(&:name)).to eq(['allow 22/tcp'])
  end

  describe 'relationships' do
    let(:catalog) { Puppet::Resource::Catalog.new }
    let(:ufw_rule) { rule(to_port: 22) }

    before(:each) { catalog.add_resource(ufw_rule) }

    it 'autorequires the ufw package and the reload exec' do
      package = Puppet::Type.type(:package).new(name: 'ufw')
      reload = Puppet::Type.type(:exec).new(name: 'ufw-reload', command: '/usr/sbin/ufw reload', refreshonly: true)
      catalog.add_resource(package, reload)
      sources = ufw_rule.autorequire.map { |e| e.source.ref }
      expect(sources).to contain_exactly('Package[ufw]', 'Exec[ufw-reload]')
    end

    it 'comes before the default policies and enabling ufw' do
      execs = ['ufw-default-incoming', 'ufw-enable'].map do |name|
        Puppet::Type.type(:exec).new(name: name, command: '/bin/true')
      end
      catalog.add_resource(*execs)
      targets = ufw_rule.autobefore.map { |e| e.target.ref }
      expect(targets).to contain_exactly('Exec[ufw-default-incoming]', 'Exec[ufw-enable]')
    end
  end
end
