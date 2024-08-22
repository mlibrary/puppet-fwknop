# Copyright (c) 2024 The Regents of the University of Michigan.
# All Rights Reserved. Licensed according to the terms of the Revised
# BSD License. See LICENSE.txt for details.

# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include fwknop
# @param pcap_intf Later
# @param enable_pcap_promisc Later
# @param pcap_filter Later
# @param enable_spa_packet_aging Later
# @param max_spa_packet_age_seconds Later
# @param enable_digest_persistence Later
# @param rules_check_threshold Later
# @param enable_ipt_forwarding Later
# @param enable_ipt_local_nat Later
# @param enable_ipt_snat Later
# @param snat_translate_ip Later
# @param enable_ipt_output Later
# @param max_sniff_bytes Later
# @param flush_ipt_at_init Later
# @param flush_ipt_at_exit Later
# @param exit_at_intf_down Later
# @param enable_rule_prepend Later
# @param enable_nat_dns Later
# @param gpg_home_dir Later
# @param gpg_exe Later
# @param locale Later
# @param enable_spa_over_http Later
# @param enable_x_forwarded_for Later
# @param enable_tcp_server Later
# @param tcpserv_port Later
# @param enable_udp_server Later
# @param udpserv_port Later
# @param pcap_dispatch_count Later
# @param pcap_loop_sleep_microseconds Later
# @param enable_pcap_any_direction Later
# @param syslog_identity Later
# @param syslog_facility Later
# @param enable_destination_rule Later
# @param fwknop_run_dir Later
# @param verbose Later
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
) {
  contain fwknop::install
  contain fwknop::config
  contain fwknop::service

  Class['fwknop::install'] -> Class['fwknop::config'] ~> Class['fwknop::service']
}
