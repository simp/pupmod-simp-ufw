# @summary A protocol for a ufw rule
type Ufw::Protocol = Enum['any', 'tcp', 'udp', 'ipv6', 'esp', 'ah', 'igmp', 'gre', 'vrrp']
