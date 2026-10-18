# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../../lib/puppet_x/ufw/rule'

describe PuppetX::Ufw::Rule do
  describe '.parse_tuple' do
    it 'parses a simple rule' do
      expect(described_class.parse_tuple('### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in', false)).to include(
        forward: false, action: 'allow', logtype: '', proto: 'tcp', dport: '22', dst: '0.0.0.0/0',
        sport: 'any', src: '0.0.0.0/0', dapp: '', sapp: '', interface_in: '', interface_out: '',
        direction: 'in', comment: ''
      )
    end

    it 'parses a routed rule with both interfaces' do
      expect(described_class.parse_tuple('### tuple ### route:allow tcp 80 10.0.0.0/8 any 0.0.0.0/0 in_eth0!out_eth1', false)).to include(
        forward: true, action: 'allow', interface_in: 'eth0', interface_out: 'eth1', direction: 'in',
      )
    end

    it 'parses log types, application names and comments' do
      expect(described_class.parse_tuple('### tuple ### allow_log-all tcp 80,443 ::/0 any ::/0 Web%20Full - out_eth0 comment=6869', true)).to include(
        v6: true, action: 'allow', logtype: 'log-all', dapp: 'Web Full', sapp: '', interface_out: 'eth0', direction: 'out', comment: 'hi',
      )
    end

    it 'ignores lines that are not tuples' do
      expect(described_class.parse_tuple('-A ufw-user-input -p tcp --dport 22 -j ACCEPT', false)).to be_nil
      expect(described_class.parse_tuple('### tuple ### allow tcp 22', false)).to be_nil
    end
  end

  describe '.normalize_address' do
    {
      ['any', false] => '0.0.0.0/0',
      ['any', true] => '::/0',
      ['10.0.0.1/32', false] => '10.0.0.1',
      ['10.1.2.3/8', false] => '10.0.0.0/8',
      ['192.168.1.0/255.255.255.0', false] => '192.168.1.0/24',
      ['2001:DB8:0:0::1/128', true] => '2001:db8::1',
      ['2001:db8::5/64', true] => '2001:db8::5/64',
      ['2001:0db8:0000:0000:0000:0000:0000:0001', true] => '2001:db8::1',
    }.each do |(addr, v6), result|
      it "normalizes #{addr} to #{result}" do
        expect(described_class.normalize_address(addr, v6)).to eq(result)
      end
    end
  end

  describe '.normalize_ports' do
    it { expect(described_class.normalize_ports(nil)).to be_nil }
    it { expect(described_class.normalize_ports(22)).to eq('22') }
    it { expect(described_class.normalize_ports('8080:8090,443,80')).to eq('80,443,8080:8090') }
    it { expect(described_class.normalize_ports([443, '80', '22:25'])).to eq('22:25,80,443') }
  end

  describe '.families' do
    it { expect(described_class.families({}, true)).to eq([false, true]) }
    it { expect(described_class.families({}, false)).to eq([false]) }
    it { expect(described_class.families({ from: '10.0.0.0/8' }, true)).to eq([false]) }
    it { expect(described_class.families({ to: '::1' }, true)).to eq([true]) }
    it { expect(described_class.families({ proto: 'igmp' }, true)).to eq([false]) }
  end

  describe '.command_args' do
    it 'renders a rule in extended syntax' do
      expect(described_class.command_args({ action: 'allow', proto: 'tcp', to_port: 22, comment: 'ssh' }))
        .to eq(['allow', 'proto', 'tcp', 'from', 'any', 'to', 'any', 'port', '22', 'comment', 'ssh'])
    end

    it 'renders a routed rule with interfaces and logging' do
      expect(described_class.command_args({ route: true, action: 'deny', direction: 'in', interface: 'eth0', out_interface: 'eth1', log: 'log' }))
        .to eq(['route', 'deny', 'in', 'on', 'eth0', 'out', 'on', 'eth1', 'log', 'from', 'any', 'to', 'any'])
    end

    it 'renders an outgoing application rule' do
      expect(described_class.command_args({ action: 'allow', direction: 'out', to: '10.0.0.1', to_app: 'Web Full' }))
        .to eq(['allow', 'out', 'from', 'any', 'to', '10.0.0.1', 'app', 'Web Full'])
    end

    it 'renders a delete without the comment' do
      expect(described_class.command_args({ action: 'limit', to_port: 22, proto: 'tcp', comment: 'x' }, delete: true))
        .to eq(['delete', 'limit', 'proto', 'tcp', 'from', 'any', 'to', 'any', 'port', '22'])
    end
  end

  describe '.match?' do
    let(:have) { described_class.parse_tuple('### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in comment=6869', false) }

    it 'matches an application rule by name, whatever its ports and comment' do
      want = described_class.desired_tuples({ action: 'allow', to_app: 'OpenSSH' }, false).first
      expect(described_class.match?(want, have)).to be true
    end

    it 'does not match a port rule against an application rule' do
      want = described_class.desired_tuples({ action: 'allow', to_port: '22', proto: 'tcp' }, false).first
      expect(described_class.match?(want, have)).to be false
    end

    it 'does not match a different action' do
      want = described_class.desired_tuples({ action: 'limit', to_app: 'OpenSSH' }, false).first
      expect(described_class.match?(want, have)).to be false
    end
  end
end
