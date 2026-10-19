#!/bin/bash
# Creates the rules captured in spec/data/ubuntu-*/. Run as root in a fresh
# docker.io/library/ubuntu:<release> container after installing the ufw and
# openssh-server packages, then save the output of `ufw show added` and the
# contents of /etc/ufw/user.rules and /etc/ufw/user6.rules.
#
# ufw is inactive in the container (it can't load iptables rules there), but
# adding rules still updates its rule files, which is all these captures need.
# In an unprivileged container ufw can't probe the kernel's capabilities and
# skips IPv6 `limit` rules, so the `limit` rule only appears in user.rules.
cat > /etc/ufw/applications.d/test-web <<'APP'
[Web Full]
title=Web Server (HTTP,HTTPS)
description=Test profile with two ports and a space in its name
ports=80,443/tcp
APP
r(){ ufw "$@" >/dev/null 2>&1 || echo "FAILED: ufw $*" >&2; }
r allow 22/tcp
r allow in on lo
r allow out on lo
r deny in from 127.0.0.0/8
r deny in from ::1
r allow out 53
r allow out to any port 443 proto tcp comment 'https out'
r limit 2222/tcp
r allow from 10.0.0.0/8 to any port 8000:8100 proto tcp
r allow from 192.168.1.0/24 to 192.168.1.5 port 8080:8090,443,80 proto tcp
r reject in on eth0 from 2001:db8::/32 to any port 25 proto tcp
r allow log 2223/tcp
r allow log-all from 1.2.3.4
r deny out log to 203.0.113.0/24
r route allow in on eth0 out on eth1 to 10.0.0.0/8 port 80 proto tcp
r route deny in on eth2
r route reject out on eth3 from 10.9.0.0/16
r allow 60000:61000/udp
r allow from 10.0.0.1 port 123 proto udp
r deny proto ipv6 from 1.2.3.4
r allow proto esp from 10.0.0.0/8
r allow OpenSSH
r allow in on eth0 to any app OpenSSH
r allow from 10.1.0.0/16 to any app OpenSSH comment 'admin net'
r allow 'Web Full'
r allow from 172.16.0.0/12 to any app 'Web Full'
r allow out on eth0 to 8.8.8.8 port 53 proto udp comment 'say "dns"'
r allow from 2001:db8:1::/48 to 2001:db8:2::1 port 443 proto tcp
