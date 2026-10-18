# frozen_string_literal: true

require 'spec_helper'

describe 'ufw::allows_ssh' do
  it { is_expected.to run.with_params({}).and_return(false) }
  it { is_expected.to run.with_params({ 'ssh' => { 'action' => 'allow', 'to_port' => 22, 'proto' => 'tcp' } }).and_return(true) }
  it { is_expected.to run.with_params({ 'ssh' => { 'action' => 'allow', 'to_port' => '22' } }).and_return(true) }
  it { is_expected.to run.with_params({ 'ssh' => { 'action' => 'allow', 'to_port' => '80,22,443', 'proto' => 'tcp' } }).and_return(true) }
  it { is_expected.to run.with_params({ 'ssh' => { 'action' => 'allow', 'to_port' => [80, '20:30'], 'proto' => 'tcp' } }).and_return(true) }
  it { is_expected.to run.with_params({ 'ssh' => { 'to_port' => 22, 'action' => 'limit', 'from' => '10.0.0.0/8' } }).and_return(true) }
  it { is_expected.to run.with_params({ 'ssh' => { 'action' => 'allow', 'to_app' => 'OpenSSH', 'interface' => 'eth0' } }).and_return(true) }
  it { is_expected.to run.with_params({ 'ssh' => { 'action' => 'allow', 'to_port' => 2222, 'proto' => 'tcp' } }, 2222).and_return(true) }

  it { is_expected.to run.with_params({ 'ssh' => { 'action' => 'allow', 'to_port' => 22, 'proto' => 'udp' } }).and_return(false) }
  it { is_expected.to run.with_params({ 'ssh' => { 'to_port' => 22, 'action' => 'deny' } }).and_return(false) }
  it { is_expected.to run.with_params({ 'ssh' => { 'action' => 'allow', 'to_port' => 22, 'ensure' => 'absent' } }).and_return(false) }
  it { is_expected.to run.with_params({ 'ssh' => { 'action' => 'allow', 'to_port' => 22, 'direction' => 'out' } }).and_return(false) }
  it { is_expected.to run.with_params({ 'ssh' => { 'action' => 'allow', 'to_port' => 22, 'route' => true } }).and_return(false) }
  it { is_expected.to run.with_params({ 'ssh' => { 'action' => 'allow', 'from_port' => 22, 'proto' => 'tcp' } }).and_return(false) }
  it { is_expected.to run.with_params({ 'ssh' => { 'action' => 'allow', 'to_port' => '2200:2300', 'proto' => 'tcp' } }).and_return(false) }
  it { is_expected.to run.with_params({ 'web' => { 'action' => 'allow', 'to_app' => 'Apache' } }).and_return(false) }

  it { is_expected.to run.with_params({ 'ssh' => { 'to_port' => 22 } }).and_return(false) }
end
