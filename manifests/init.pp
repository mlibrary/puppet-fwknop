# Copyright (c) 2024 The Regents of the University of Michigan.
# All Rights Reserved. Licensed according to the terms of the Revised
# BSD License. See LICENSE.txt for details.

# fwknop
#
# Install fwknop and manage its 2 config files.
#
# @example
#   include fwknop
#
# @param pcap_intf
#   Define the ethernet interface on which we will sniff packets.
#   Default if not set is the networking.primary fact.
#
# @param enable_pcap_promisc
#   If true, put the pcap interface into promiscuous mode. If false,
#   don't. The man page for fwknopd says this is default enabled, but
#   the debian config file says it's default disabled. Good luck.
#
# @param pcap_filter
#   Define the filter used for PCAP modes; we default to udp port 62201.
#   However, if an fwknop client uses the --rand-port option to send the
#   SPA packet over a random port, then this parameter should be updated
#   to something like "udp dst portrange 10000-65535;".
#   Default is "udp port 62201".
#
# @param enable_spa_packet_aging
#   This instructs fwknopd to not honor SPA packets that have an old
#   time stamp. The value for "old" is defined by the max_spa_packet_age
#   parameter. If enable_spa_packet_aging is set to false, fwknopd will
#   not use the client time stamp at all.
#
# @param max_spa_packet_age_seconds
#   Defines the maximum age (in seconds) that an SPA packet will be
#   accepted. This requires that the client system is in relatively
#   close time synchronization with the fwknopd server system (NTP is
#   good). The default age is two minutes.
#
# @param enable_digest_persistence
#   Track digest sums associated with previous fwknop process. This
#   allows digest sums to remain persistent across executions of fwknop.
#
# @param rules_check_threshold
#   Defines the number of times firewall rule expiration times must be
#   checked before a "deep" check is run. This allows fwknopd to remove
#   rules that contain a proper exp<time> even if a third party program
#   added them instead of fwknopd. The default value for this variable
#   is 20, and this typically results in this check being run every two
#   seconds or so. To disable this type of checking altogether, set this
#   variable to zero.
#
# @param enable_ipt_forwarding
#   Allow SPA clients to request access to services through an
#   iptables firewall instead of just to it (i.e. access through
#   the FWKNOP_FORWARD chain instead of the INPUT chain).
#
# @param enable_ipt_local_nat
#   Allow SPA clients to request access to a local socket via NAT.
#   This still puts an ACCEPT rule into the FWKNOP_INPUT chain, but a
#   different port is translated via DNAT rules to the real one. So, the
#   user would do "ssh -p <port>" to access the local service (see the
#   --NAT-local and --NAT-rand-port on the fwknop client command line).
#
# @param enable_ipt_snat
#   By default, if forwarding access is enabled (see the
#   enable_ipt_forwarding parameter), then fwknop creates DNAT rules for
#   incoming connections, but does not also complement these rules with
#   SNAT rules at the same time. In some situations, internal systems
#   may not have a route back out for the source address of the incoming
#   connection, so it is necessary to also apply SNAT rules so that the
#   internal systems see the IP of the internal interface where fwknopd
#   is running. This functionality is only enabled when enable_ipt_snat
#   is set to true, and by default SNAT rules are built with the
#   MASQUERADE target (since then the internal IP does not have to be
#   defined here in the fwknop.conf file), but if you want fwknopd to
#   use the SNAT target then also define an IP address with the
#   snat_translate_ip parameter.
#
# @param snat_translate_ip
#   The IP address to use when enable_ipt_snat is true.
#
# @param enable_ipt_output
#   Add ACCEPT rules to the FWKNOP_OUTPUT chain. This is usually only
#   useful if there are no state tracking rules to allow connection
#   responses out and the OUTPUT chain has a default-drop stance.
#
# @param max_sniff_bytes
#   Specify the the maximum number of bytes to sniff per frame - 1500 is
#   a good default
#
# @param flush_ipt_at_init
#   Flush all existing rules in the fwknop chains at fwknop start time.
#   Defaults to true and it is a recommended setting.
#
# @param flush_ipt_at_exit
#   Flush all existing rules in the fwknop chains at fwknop exit time.
#   Defaults to true and it is a recommended setting.
#
# @param exit_at_intf_down
#   When fwknopd is sniffing an interface, if the interface is
#   administratively downed or unplugged, fwknopd will cleanly exit and
#   an assumption is made that any process monitoring infrastructure
#   like systemd or upstart will restart it. However, if fwknopd is not
#   being monitored by systemd, upstart, or anything else, this behavior
#   can be disabled with the exit_at_intf_down parameter. If disabled,
#   fwknopd will try to recover when a downed interface comes back up.
#
# @param enable_rule_prepend
#   Instead of appending new firewall rules to the bottom of the chain,
#   this option inserts rules at the top of the chain. This causes newly
#   created rules to have precedence over older ones.
#
# @param enable_nat_dns
#   Allow fwknopd to resolve hostnames in NAT access messages.
#
# @param gpg_home_dir
#   If GPG keys are used instead of a Rijndael symmetric key, this is
#   the default GPG keys directory. Note that each access stanza in
#   fwknop access.conf can specify its own GPG directory to override
#   this default.
#
# @param gpg_exe
#   Set the default GPG path when GPG is used for SPA encryption
#   and authentication.
#
# @param locale
#   Set/override the locale (via the LC_ALL locale category). Leave this
#   entry undefined to have fwknopd honor the default system locale.
#
# @param enable_spa_over_http
#   Allow fwknopd to acquire SPA data from HTTP requests (generated with
#   the fwknop client in --HTTP mode). Note that the pcap_filter
#   parameter would need to be updated when this is enabled to sniff
#   traffic over TCP/80 connections.
#
# @param enable_x_forwarded_for
#   Allows the use of the X-Forwarded-for header from a captured
#   packet as the Source IP. This can happen when using SPA through
#   an HTTP proxy.
#
# @param enable_tcp_server
#   Enable the fwknopd TCP server. This is a "dummy" TCP server that
#   will accept TCP connection requests on the specified tcpserv_port.
#   If set to true, fwknopd will fork off a child process to listen for
#   and accept incoming TCP requests. This server only accepts the
#   request. It does not otherwise communicate. This is only to allow
#   the incoming SPA over TCP packet which is detected via PCAP. The
#   connection is closed after 1 second regardless. Note that fwknopd
#   still only gets its data via pcap, so the filter defined by
#   pcap_filter needs to be updated to include this TCP port.
#
# @param tcpserv_port
#   The port for the TCP server if enable_tcp_server is true.
#
# @param enable_udp_server
#   This is probably similar to enable_tcp_server but UDP.
#
# @param udpserv_port
#   The port for the UDP server if enable_udp_server is true.
#
# @param pcap_dispatch_count
#   Sets the number of packets that are processed when the
#   pcap_dispatch() call is made. The default is zero, since this allows
#   fwknopd to process as many packets as possible in the corresponding
#   callback where the SPA handling routine is called for packets that
#   pass a set of prerequisite checks. However, if fwknopd is running on
#   a platform with an old version of libpcap, it may be necessary to
#   change this value to a positive non-zero integer. More information
#   can be found in the pcap_dispatch(3) man page.
#
# @param pcap_loop_sleep_microseconds
#   Sets the number of microseconds to pass as an argument to usleep()
#   in the pcap loop. The default is 100000 microseconds, or 1/10th of
#   a second.
#
# @param enable_pcap_any_direction
#   This parameter controls whether fwknopd is permitted to sniff SPA
#   packets regardless of whether they are received on the sniffing
#   interface or sent from the sniffing interface. In the latter case,
#   this can be useful to have fwknopd sniff SPA packets that are
#   forwarded through a system and destined for a different network. If
#   the sniffing interface is the egress interface for such packets,
#   then this parameter will need to be set to true in order for fwknopd
#   to see them. The default is false so that fwknopd only looks for SPA
#   packets that are received on the sniffing interface (note that this
#   is independent of promiscuous mode).
#
# @param syslog_identity
#   Override syslog identity (the defaults are usually ok).
#
# @param syslog_facility
#   Override syslog facility (the defaults are usually ok). The
#   syslog_facility parameter can be set to one of LOG_LOCAL{0-7} or
#   LOG_DAEMON (the default).
#
# @param enable_destination_rule
#   Controls whether fwknopd will set the destination field on the
#   firewall rule to the destination address specified on the incoming
#   SPA packet. This is useful for interfaces with multiple IP addresses
#   hosting separate services. If enable_ipt_output is set to true, the
#   source field of the firewall rule is set. FORWARD and SNAT rules are
#   not affected however, DNAT rules will also have their destination
#   field set. The default is false, which sets the destination field
#   to 0.0.0.0/0 (any).
#
# @param fwknop_run_dir
#   Defaults to /var/run/fwknop
#
# @param verbose
#   Define the default verbosity level the fwknop server should use. A
#   value of 0 is the default verbosity level. Setting it up to 1 or
#   higher will allow debugging messages to be displayed.
#
# @param package_manage
#   Whether to manage the fwknop-server package. Default true.
#
# @param service_manage
#   Whether to manage the fwknop-server service. Default true.
#
class fwknop (
  Optional[String] $pcap_intf = undef,
  Optional[Boolean] $enable_pcap_promisc = undef,
  Optional[Variant[Sensitive[String], String]] $pcap_filter = undef,
  Optional[Boolean] $enable_spa_packet_aging = undef,
  Optional[Integer] $max_spa_packet_age_seconds = undef,
  Optional[Boolean] $enable_digest_persistence = undef,
  Optional[Integer] $rules_check_threshold = undef,
  Optional[Boolean] $enable_ipt_forwarding = undef,
  Optional[Boolean] $enable_ipt_local_nat = undef,
  Optional[Boolean] $enable_ipt_snat = undef,
  Optional[String] $snat_translate_ip = undef,
  Optional[Boolean] $enable_ipt_output = undef,
  Optional[Integer] $max_sniff_bytes = undef,
  Optional[Boolean] $flush_ipt_at_init = undef,
  Optional[Boolean] $flush_ipt_at_exit = undef,
  Optional[Boolean] $exit_at_intf_down = undef,
  Optional[Boolean] $enable_rule_prepend = undef,
  Optional[Boolean] $enable_nat_dns = undef,
  Optional[String] $gpg_home_dir = undef,
  Optional[String] $gpg_exe = undef,
  Optional[String] $locale = undef,
  Optional[Boolean] $enable_spa_over_http = undef,
  Optional[Boolean] $enable_x_forwarded_for = undef,
  Optional[Boolean] $enable_tcp_server = undef,
  Optional[Integer] $tcpserv_port = undef,
  Optional[Boolean] $enable_udp_server = undef,
  Optional[Integer] $udpserv_port = undef,
  Optional[Integer] $pcap_dispatch_count = undef,
  Optional[Integer] $pcap_loop_sleep_microseconds = undef,
  Optional[Boolean] $enable_pcap_any_direction = undef,
  Optional[String] $syslog_identity = undef,
  Optional[String] $syslog_facility = undef,
  Optional[Boolean] $enable_destination_rule = undef,
  Optional[String] $fwknop_run_dir = undef,
  Optional[Integer] $verbose = undef,
  Boolean $package_manage = true,
  Boolean $service_manage = true,
) {
  contain fwknop::install
  contain fwknop::config
  contain fwknop::service

  Class['fwknop::install'] -> Class['fwknop::config'] ~> Class['fwknop::service']
}
