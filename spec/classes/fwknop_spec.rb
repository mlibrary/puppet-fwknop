# frozen_string_literal: true

# Copyright (c) 2024 The Regents of the University of Michigan.
# All Rights Reserved. Licensed according to the terms of the Revised
# BSD License. See LICENSE.txt for details.

require 'spec_helper'

describe 'fwknop' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      context 'with no explicit parameters' do
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('Fwknop::Install') }
        it { is_expected.to contain_class('Fwknop::Service') }
        it { is_expected.to contain_class('Fwknop::Config').that_requires('Class[Fwknop::Install]') }
        it { is_expected.to contain_class('Fwknop::Config').that_notifies('Class[Fwknop::Service]') }

        it { is_expected.to contain_package('fwknop-server') }
        it { is_expected.to contain_service('fwknop-server') }

        it { is_expected.to contain_file('/etc/fwknop').with_ensure('directory') }

        it { is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_owner('root') }
        it { is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_group('root') }
        it { is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_mode('0600') }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
            FWKNOPD
          )
        end

        it { is_expected.to contain_concat('/etc/fwknop/access.conf').with_owner('root') }
        it { is_expected.to contain_concat('/etc/fwknop/access.conf').with_group('root') }
        it { is_expected.to contain_concat('/etc/fwknop/access.conf').with_mode('0600') }
        it { is_expected.to contain_concat__fragment('000 fwknop access header').with_target('/etc/fwknop/access.conf') }
        it { is_expected.to contain_concat__fragment('000 fwknop access header').with_order('000') }
        it { is_expected.to contain_concat__fragment('000 fwknop access header').with_content("# Managed by puppet.\n") }
      end

      context 'with package_manage set to false' do
        let(:params) { { package_manage: false } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_package('fwknop-server') }
      end

      context 'with service_manage set to false' do
        let(:params) { { service_manage: false } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_service('fwknop-server') }
      end

      context 'with pcap_intf set to eth5' do
        let(:params) { { pcap_intf: 'eth5' } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 eth5;
            FWKNOPD
          )
        end
      end

      context 'with enable_pcap_promisc set to true' do
        let(:params) { { enable_pcap_promisc: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_PCAP_PROMISC       Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_pcap_promisc set to false' do
        let(:params) { { enable_pcap_promisc: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_PCAP_PROMISC       N;
            FWKNOPD
          )
        end
      end

      context 'with pcap_filter set to udp port 62201' do
        let(:params) { { pcap_filter: 'udp port 62201' } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              PCAP_FILTER               udp port 62201;
            FWKNOPD
          )
        end
      end

      context 'with pcap_filter set to sensitive(tcp port 62202)' do
        let(:params) { { pcap_filter: sensitive('tcp port 62202') } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              PCAP_FILTER               tcp port 62202;
            FWKNOPD
          )
        end
      end

      context 'with enable_spa_packet_aging set to true' do
        let(:params) { { enable_spa_packet_aging: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_SPA_PACKET_AGING   Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_spa_packet_aging set to false' do
        let(:params) { { enable_spa_packet_aging: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_SPA_PACKET_AGING   N;
            FWKNOPD
          )
        end
      end

      context 'with max_spa_packet_age_seconds set to 120' do
        let(:params) { { max_spa_packet_age_seconds: 120 } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              MAX_SPA_PACKET_AGE        120;
            FWKNOPD
          )
        end
      end

      context 'with enable_digest_persistence set to true' do
        let(:params) { { enable_digest_persistence: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_DIGEST_PERSISTENCE Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_digest_persistence set to false' do
        let(:params) { { enable_digest_persistence: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_DIGEST_PERSISTENCE N;
            FWKNOPD
          )
        end
      end

      context 'with rules_check_threshold set to 20' do
        let(:params) { { rules_check_threshold: 20 } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              RULES_CHECK_THRESHOLD     20;
            FWKNOPD
          )
        end
      end

      context 'with enable_ipt_forwarding set to true' do
        let(:params) { { enable_ipt_forwarding: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_IPT_FORWARDING     Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_ipt_forwarding set to false' do
        let(:params) { { enable_ipt_forwarding: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_IPT_FORWARDING     N;
            FWKNOPD
          )
        end
      end

      context 'with enable_ipt_local_nat set to true' do
        let(:params) { { enable_ipt_local_nat: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_IPT_LOCAL_NAT      Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_ipt_local_nat set to false' do
        let(:params) { { enable_ipt_local_nat: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_IPT_LOCAL_NAT      N;
            FWKNOPD
          )
        end
      end

      context 'with enable_ipt_snat set to true' do
        let(:params) { { enable_ipt_snat: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_IPT_SNAT           Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_ipt_snat set to false' do
        let(:params) { { enable_ipt_snat: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_IPT_SNAT           N;
            FWKNOPD
          )
        end
      end

      context 'with snat_translate_ip set to 10.1.2.3' do
        let(:params) { { snat_translate_ip: '10.1.2.3' } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              SNAT_TRANSLATE_IP         10.1.2.3;
            FWKNOPD
          )
        end
      end

      context 'with enable_ipt_output set to true' do
        let(:params) { { enable_ipt_output: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_IPT_OUTPUT         Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_ipt_output set to false' do
        let(:params) { { enable_ipt_output: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_IPT_OUTPUT         N;
            FWKNOPD
          )
        end
      end

      context 'with max_sniff_bytes set to 1500' do
        let(:params) { { max_sniff_bytes: 1500 } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              MAX_SNIFF_BYTES           1500;
            FWKNOPD
          )
        end
      end

      context 'with flush_ipt_at_init set to true' do
        let(:params) { { flush_ipt_at_init: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              FLUSH_IPT_AT_INIT         Y;
            FWKNOPD
          )
        end
      end

      context 'with flush_ipt_at_init set to false' do
        let(:params) { { flush_ipt_at_init: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              FLUSH_IPT_AT_INIT         N;
            FWKNOPD
          )
        end
      end

      context 'with flush_ipt_at_exit set to true' do
        let(:params) { { flush_ipt_at_exit: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              FLUSH_IPT_AT_EXIT         Y;
            FWKNOPD
          )
        end
      end

      context 'with flush_ipt_at_exit set to false' do
        let(:params) { { flush_ipt_at_exit: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              FLUSH_IPT_AT_EXIT         N;
            FWKNOPD
          )
        end
      end

      context 'with exit_at_intf_down set to true' do
        let(:params) { { exit_at_intf_down: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              EXIT_AT_INTF_DOWN         Y;
            FWKNOPD
          )
        end
      end

      context 'with exit_at_intf_down set to false' do
        let(:params) { { exit_at_intf_down: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              EXIT_AT_INTF_DOWN         N;
            FWKNOPD
          )
        end
      end

      context 'with enable_rule_prepend set to true' do
        let(:params) { { enable_rule_prepend: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_RULE_PREPEND       Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_rule_prepend set to false' do
        let(:params) { { enable_rule_prepend: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_RULE_PREPEND       N;
            FWKNOPD
          )
        end
      end

      context 'with enable_nat_dns set to true' do
        let(:params) { { enable_nat_dns: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_NAT_DNS            Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_nat_dns set to false' do
        let(:params) { { enable_nat_dns: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_NAT_DNS            N;
            FWKNOPD
          )
        end
      end

      context 'with gpg_home_dir set to /var/lib/gnupg' do
        let(:params) { { gpg_home_dir: '/var/lib/gnupg' } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              GPG_HOME_DIR              /var/lib/gnupg;
            FWKNOPD
          )
        end
      end

      context 'with gpg_exe set to /usr/local/bin/gpg' do
        let(:params) { { gpg_exe: '/usr/local/bin/gpg' } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              GPG_EXE                   /usr/local/bin/gpg;
            FWKNOPD
          )
        end
      end

      context 'with locale set to C' do
        let(:params) { { locale: 'C' } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              LOCALE                    C;
            FWKNOPD
          )
        end
      end

      context 'with enable_spa_over_http set to true' do
        let(:params) { { enable_spa_over_http: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_SPA_OVER_HTTP      Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_spa_over_http set to false' do
        let(:params) { { enable_spa_over_http: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_SPA_OVER_HTTP      N;
            FWKNOPD
          )
        end
      end

      context 'with enable_x_forwarded_for set to true' do
        let(:params) { { enable_x_forwarded_for: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_X_FORWARDED_FOR    Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_x_forwarded_for set to false' do
        let(:params) { { enable_x_forwarded_for: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_X_FORWARDED_FOR    N;
            FWKNOPD
          )
        end
      end

      context 'with enable_tcp_server set to true' do
        let(:params) { { enable_tcp_server: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_TCP_SERVER         Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_tcp_server set to false' do
        let(:params) { { enable_tcp_server: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_TCP_SERVER         N;
            FWKNOPD
          )
        end
      end

      context 'with tcpserv_port set to 8080' do
        let(:params) { { tcpserv_port: 8080 } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              TCPSERV_PORT              8080;
            FWKNOPD
          )
        end
      end

      context 'with enable_udp_server set to true' do
        let(:params) { { enable_udp_server: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_UDP_SERVER         Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_udp_server set to false' do
        let(:params) { { enable_udp_server: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_UDP_SERVER         N;
            FWKNOPD
          )
        end
      end

      context 'with udpserv_port set to 4567' do
        let(:params) { { udpserv_port: 4567 } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              UDPSERV_PORT              4567;
            FWKNOPD
          )
        end
      end

      context 'with pcap_dispatch_count set to 0' do
        let(:params) { { pcap_dispatch_count: 0 } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              PCAP_DISPATCH_COUNT       0;
            FWKNOPD
          )
        end
      end

      context 'with pcap_loop_sleep_microseconds set to 100000' do
        let(:params) { { pcap_loop_sleep_microseconds: 100_000 } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              PCAP_LOOP_SLEEP           100000;
            FWKNOPD
          )
        end
      end

      context 'with enable_pcap_any_direction set to true' do
        let(:params) { { enable_pcap_any_direction: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_PCAP_ANY_DIRECTION Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_pcap_any_direction set to false' do
        let(:params) { { enable_pcap_any_direction: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_PCAP_ANY_DIRECTION N;
            FWKNOPD
          )
        end
      end

      context 'with syslog_identity set to fwknopd' do
        let(:params) { { syslog_identity: 'fwknopd' } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              SYSLOG_IDENTITY           fwknopd;
            FWKNOPD
          )
        end
      end

      context 'with syslog_facility set to LOG_DAEMON' do
        let(:params) { { syslog_facility: 'LOG_DAEMON' } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              SYSLOG_FACILITY           LOG_DAEMON;
            FWKNOPD
          )
        end
      end

      context 'with enable_destination_rule set to true' do
        let(:params) { { enable_destination_rule: true } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_DESTINATION_RULE   Y;
            FWKNOPD
          )
        end
      end

      context 'with enable_destination_rule set to false' do
        let(:params) { { enable_destination_rule: false } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              ENABLE_DESTINATION_RULE   N;
            FWKNOPD
          )
        end
      end

      context 'with fwknop_run_dir set to /var/run' do
        let(:params) { { fwknop_run_dir: '/var/run' } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              PCAP_INTF                 #{facts[:networking]['primary']};
              FWKNOP_RUN_DIR            /var/run;
            FWKNOPD
          )
        end
      end

      context 'with verbose set to 1' do
        let(:params) { { verbose: 1 } }

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_file('/etc/fwknop/fwknopd.conf').with_content(
            <<~FWKNOPD
              # Managed by puppet.
              VERBOSE                   1;
              PCAP_INTF                 #{facts[:networking]['primary']};
            FWKNOPD
          )
        end
      end
    end
  end
end
