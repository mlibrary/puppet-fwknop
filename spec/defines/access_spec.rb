# frozen_string_literal: true

# Copyright (c) 2024 The Regents of the University of Michigan.
# All Rights Reserved. Licensed according to the terms of the Revised
# BSD License. See LICENSE.txt for details.

require 'spec_helper'

describe 'fwknop::access' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:add_access_config) { contain_concat__fragment("fwknop access #{title}") }

      context 'with title set to "testing required fields"' do
        let(:title) { 'testing required fields' }

        context 'with no parameters set' do
          it { is_expected.not_to compile }
        end

        context 'with key set' do
          let(:params) { { key: 'example' } }

          it { is_expected.to compile }
          it { is_expected.to add_access_config.with_target('/etc/fwknop/access.conf') }
          it { is_expected.to add_access_config.with_order('10') }

          it do
            is_expected.to add_access_config.with_content(
              <<~ACCESS

                # testing required fields
                SOURCE                      ANY
                KEY                         example
              ACCESS
            )
          end

          context 'with key_base64 set' do
            let(:params) { super().merge(key_base64: 'example=') }

            it { is_expected.not_to compile }
          end

          context 'with gpg_decrypt_id set' do
            let(:params) { super().merge(gpg_decrypt_id: 'acbd1234') }

            it { is_expected.not_to compile }
          end

          context 'with order set to 111' do
            let(:params) { super().merge(order: '111') }

            it { is_expected.to compile }
            it { is_expected.to add_access_config.with_order('111') }
          end
        end

        context 'with key_base64 set' do
          let(:params) { { key_base64: 'example=' } }

          it { is_expected.to compile }
          it { is_expected.to add_access_config.with_target('/etc/fwknop/access.conf') }
          it { is_expected.to add_access_config.with_order('10') }

          it do
            is_expected.to add_access_config.with_content(
              <<~ACCESS

                # testing required fields
                SOURCE                      ANY
                KEY_BASE64                  example=
              ACCESS
            )
          end

          context 'with key set' do
            let(:params) { super().merge(key: 'example') }

            it { is_expected.not_to compile }
          end

          context 'with gpg_decrypt_id set' do
            let(:params) { super().merge(gpg_decrypt_id: 'acbd1234') }

            it { is_expected.not_to compile }
          end
        end

        context 'with gpg_decrypt_id set' do
          let(:params) { { gpg_decrypt_id: 'abcd1234', gpg_decrypt_pw: 'efgh5678' } }

          it { is_expected.to compile }
          it { is_expected.to add_access_config.with_target('/etc/fwknop/access.conf') }
          it { is_expected.to add_access_config.with_order('10') }

          it do
            is_expected.to add_access_config.with_content(
              <<~ACCESS

                # testing required fields
                SOURCE                      ANY
                GPG_DECRYPT_ID              abcd1234
                GPG_DECRYPT_PW              efgh5678
              ACCESS
            )
          end

          context 'with key set' do
            let(:params) { super().merge(key: 'example') }

            it { is_expected.not_to compile }
          end

          context 'with key_base64 set' do
            let(:params) { super().merge(key_base64: 'example=') }

            it { is_expected.not_to compile }
          end
        end
      end

      context 'with title set to "checking each parameter"' do
        let(:title) { 'checking each parameter' }

        context 'with key set to sensitive(gbonnczh9sxe8xkzzdy3waqwb6qb7uxr)' do
          let(:params) { { key: sensitive('gbonnczh9sxe8xkzzdy3waqwb6qb7uxr') } }

          it { is_expected.to compile }

          it do
            is_expected.to add_access_config.with_content(
              <<~ACCESS

                # checking each parameter
                SOURCE                      ANY
                KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
              ACCESS
            )
          end

          context 'with source set to 10.0.0.0/8' do
            let(:params) { super().merge(source: '10.0.0.0/8') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      10.0.0.0/8
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                ACCESS
              )
            end
          end

          context 'with destination set to 10.1.2.3' do
            let(:params) { super().merge(destination: '10.1.2.3') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  DESTINATION                 10.1.2.3
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                ACCESS
              )
            end
          end

          context 'with open_ports set to tcp/22' do
            let(:params) { super().merge(open_ports: 'tcp/22') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  OPEN_PORTS                  tcp/22
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                ACCESS
              )
            end
          end

          context 'with restrict_ports set to udp/67' do
            let(:params) { super().merge(restrict_ports: 'udp/67') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  RESTRICT_PORTS              udp/67
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                ACCESS
              )
            end
          end

          context 'with hmac_key set to wk5w6pac5rxzw9euj98bc7z94h16shnfgnnw86ff1atuukdridww7uq85ez556py' do
            let(:params) { super().merge(hmac_key: 'wk5w6pac5rxzw9euj98bc7z94h16shnfgnnw86ff1atuukdridww7uq85ez556py') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  HMAC_KEY                    wk5w6pac5rxzw9euj98bc7z94h16shnfgnnw86ff1atuukdridww7uq85ez556py
                ACCESS
              )
            end
          end

          context 'with hmac_key set to sensitive(gxpqf5ctz3sa469qdfsbee6h17zi16egaofom9ces4gqqd78rc4beaz48qmz8oi7)' do
            let(:params) { super().merge(hmac_key: sensitive('gxpqf5ctz3sa469qdfsbee6h17zi16egaofom9ces4gqqd78rc4beaz48qmz8oi7')) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  HMAC_KEY                    gxpqf5ctz3sa469qdfsbee6h17zi16egaofom9ces4gqqd78rc4beaz48qmz8oi7
                ACCESS
              )
            end
          end

          context 'with hmac_key_base64 set to yZCbmQbzphgpmo7KmwiJsIXNTttwf4Gjk/5jLqr95Sq0MUE79RZLOR1SJMpxJIctrbHXH1IT9u9+VvWvBOG0yw==' do
            let(:params) { super().merge(hmac_key_base64: 'yZCbmQbzphgpmo7KmwiJsIXNTttwf4Gjk/5jLqr95Sq0MUE79RZLOR1SJMpxJIctrbHXH1IT9u9+VvWvBOG0yw==') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  HMAC_KEY_BASE64             yZCbmQbzphgpmo7KmwiJsIXNTttwf4Gjk/5jLqr95Sq0MUE79RZLOR1SJMpxJIctrbHXH1IT9u9+VvWvBOG0yw==
                ACCESS
              )
            end
          end

          context 'with hmac_key_base64 set to sensitive(MyIkbucl9iGS6Mo6tNMx7WO2V78YxmcJw5vkbQ6tRdRZSp5u1/UIJaFgU1R6XZ3940X5bvG/1LRMqxDhuLPF4Q==)' do
            let(:params) { super().merge(hmac_key_base64: sensitive('MyIkbucl9iGS6Mo6tNMx7WO2V78YxmcJw5vkbQ6tRdRZSp5u1/UIJaFgU1R6XZ3940X5bvG/1LRMqxDhuLPF4Q==')) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  HMAC_KEY_BASE64             MyIkbucl9iGS6Mo6tNMx7WO2V78YxmcJw5vkbQ6tRdRZSp5u1/UIJaFgU1R6XZ3940X5bvG/1LRMqxDhuLPF4Q==
                ACCESS
              )
            end
          end

          context 'with fw_access_timeout_seconds set to 30' do
            let(:params) { super().merge(fw_access_timeout_seconds: 30) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  FW_ACCESS_TIMEOUT           30
                ACCESS
              )
            end
          end

          context 'with include set to /home/cooldude/.access.conf' do
            let(:params) { super().merge(include: '/home/cooldude/.access.conf') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  %include                    /home/cooldude/.access.conf
                ACCESS
              )
            end
          end

          context 'with include_folder set to /usr/local/fwknop_access' do
            let(:params) { super().merge(include_folder: '/usr/local/fwknop_access') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  %include_folder             /usr/local/fwknop_access
                ACCESS
              )
            end
          end

          context 'with encryption_mode set to CBC' do
            let(:params) { super().merge(encryption_mode: 'CBC') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  ENCRYPTION_MODE             CBC
                ACCESS
              )
            end
          end

          context 'with hmac_digest_type set to SHA256' do
            let(:params) { super().merge(hmac_digest_type: 'SHA256') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  HMAC_DIGEST_TYPE            SHA256
                ACCESS
              )
            end
          end

          context 'with access_expire set to 01/01/1999' do
            let(:params) { super().merge(access_expire: '01/01/1999') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  ACCESS_EXPIRE               01/01/1999
                ACCESS
              )
            end
          end

          context 'with access_expire_epoch set to 915166800' do
            let(:params) { super().merge(access_expire_epoch: 915_166_800) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  ACCESS_EXPIRE_EPOCH         915166800
                ACCESS
              )
            end
          end

          context 'with enable_cmd_exec set to true' do
            let(:params) { super().merge(enable_cmd_exec: true) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  ENABLE_CMD_EXEC             Y
                ACCESS
              )
            end
          end

          context 'with enable_cmd_exec set to false' do
            let(:params) { super().merge(enable_cmd_exec: false) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  ENABLE_CMD_EXEC             N
                ACCESS
              )
            end
          end

          context 'with enable_cmd_sudo_exec set to true' do
            let(:params) { super().merge(enable_cmd_sudo_exec: true) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  ENABLE_CMD_SUDO_EXEC        Y
                ACCESS
              )
            end
          end

          context 'with enable_cmd_sudo_exec set to false' do
            let(:params) { super().merge(enable_cmd_sudo_exec: false) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  ENABLE_CMD_SUDO_EXEC        N
                ACCESS
              )
            end
          end

          context 'with cmd_exec_user set to eg_username' do
            let(:params) { super().merge(cmd_exec_user: 'eg_username') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  CMD_EXEC_USER               eg_username
                ACCESS
              )
            end
          end

          context 'with cmd_sudo_exec_user set to eg_username' do
            let(:params) { super().merge(cmd_sudo_exec_user: 'eg_username') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  CMD_SUDO_EXEC_USER          eg_username
                ACCESS
              )
            end
          end

          context 'with cmd_exec_group set to eg_group' do
            let(:params) { super().merge(cmd_exec_group: 'eg_group') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  CMD_EXEC_GROUP              eg_group
                ACCESS
              )
            end
          end

          context 'with cmd_sudo_exec_group set to eg_group' do
            let(:params) { super().merge(cmd_sudo_exec_group: 'eg_group') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  CMD_SUDO_EXEC_GROUP         eg_group
                ACCESS
              )
            end
          end

          context 'with cmd_cycle_open set to echo' do
            let(:params) { super().merge(cmd_cycle_open: 'echo open $DST:$PROTO/$PORT to $SRC for $TIMEOUT seconds thanks to $PKT_SRC') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  CMD_CYCLE_OPEN              echo open $DST:$PROTO/$PORT to $SRC for $TIMEOUT seconds thanks to $PKT_SRC
                ACCESS
              )
            end
          end

          context 'with cmd_cycle_close set to NONE' do
            let(:params) { super().merge(cmd_cycle_close: 'NONE') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  CMD_CYCLE_CLOSE             NONE
                ACCESS
              )
            end
          end

          context 'with cmd_cycle_timer_seconds set to 45' do
            let(:params) { super().merge(cmd_cycle_timer_seconds: 45) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  CMD_CYCLE_TIMER             45
                ACCESS
              )
            end
          end

          context 'with sudo_exe set to /usr/local/bin/sudo' do
            let(:params) { super().merge(sudo_exe: '/usr/local/bin/sudo') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  SUDO_EXE                    /usr/local/bin/sudo
                ACCESS
              )
            end
          end

          context 'with require_username set to cooldude' do
            let(:params) { super().merge(require_username: 'cooldude') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  REQUIRE_USERNAME            cooldude
                ACCESS
              )
            end
          end

          context 'with require_source_address set to true' do
            let(:params) { super().merge(require_source_address: true) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  REQUIRE_SOURCE_ADDRESS      Y
                ACCESS
              )
            end
          end

          context 'with require_source_address set to false' do
            let(:params) { super().merge(require_source_address: false) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  REQUIRE_SOURCE_ADDRESS      N
                ACCESS
              )
            end
          end

          context 'with force_nat set to 10.1.2.3 25' do
            let(:params) { super().merge(force_nat: '10.1.2.3 25') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  FORCE_NAT                   10.1.2.3 25
                ACCESS
              )
            end
          end

          context 'with force_snat set to 10.4.5.6' do
            let(:params) { super().merge(force_snat: '10.4.5.6') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  FORCE_SNAT                  10.4.5.6
                ACCESS
              )
            end
          end

          context 'with force_masquerade set to true' do
            let(:params) { super().merge(force_masquerade: true) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  FORCE_MASQUERADE            Y
                ACCESS
              )
            end
          end

          context 'with force_masquerade set to false' do
            let(:params) { super().merge(force_masquerade: false) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  FORCE_MASQUERADE            N
                ACCESS
              )
            end
          end

          context 'with forward_all set to true' do
            let(:params) { super().merge(forward_all: true) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  FORWARD_ALL                 Y
                ACCESS
              )
            end
          end

          context 'with forward_all set to false' do
            let(:params) { super().merge(forward_all: false) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  FORWARD_ALL                 N
                ACCESS
              )
            end
          end

          context 'with disable_dnat set to true' do
            let(:params) { super().merge(disable_dnat: true) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  DISABLE_DNAT                Y
                ACCESS
              )
            end
          end

          context 'with disable_dnat set to false' do
            let(:params) { super().merge(disable_dnat: false) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  KEY                         gbonnczh9sxe8xkzzdy3waqwb6qb7uxr
                  DISABLE_DNAT                N
                ACCESS
              )
            end
          end
        end

        context 'with key_base64 set to sensitive(o3K4WPGWGL46dLtwQnEHEgnkR6T1z1kMCkOGUzDAg9E=)' do
          let(:params) { { key_base64: sensitive('o3K4WPGWGL46dLtwQnEHEgnkR6T1z1kMCkOGUzDAg9E=') } }

          it { is_expected.to compile }

          it do
            is_expected.to add_access_config.with_content(
              <<~ACCESS

                # checking each parameter
                SOURCE                      ANY
                KEY_BASE64                  o3K4WPGWGL46dLtwQnEHEgnkR6T1z1kMCkOGUzDAg9E=
              ACCESS
            )
          end
        end

        context 'with gpg_decrypt_id set to bcd35d73e538b5b5a53bee711b567de9c5eaa20b' do
          let(:params) { { gpg_decrypt_id: 'bcd35d73e538b5b5a53bee711b567de9c5eaa20b' } }

          it { is_expected.not_to compile }

          context 'with gpg_decrypt_pw set to r6k9sctpq7sftt37pp6urer6g8' do
            let(:params) { super().merge(gpg_decrypt_pw: 'r6k9sctpq7sftt37pp6urer6g8') }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                  GPG_DECRYPT_PW              r6k9sctpq7sftt37pp6urer6g8
                ACCESS
              )
            end
          end

          context 'with gpg_decrypt_pw set to sensitive(n1ots9rgrbmmeuzewditpbw7xo)' do
            let(:params) { super().merge(gpg_decrypt_pw: sensitive('n1ots9rgrbmmeuzewditpbw7xo')) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                  GPG_DECRYPT_PW              n1ots9rgrbmmeuzewditpbw7xo
                ACCESS
              )
            end
          end

          context 'with gpg_allow_no_pw set to false' do
            let(:params) { super().merge(gpg_allow_no_pw: false) }

            it { is_expected.not_to compile }

            context 'with gpg_decrypt_pw set to anscxk7aeu8ystoz1gtuere7zh' do
              let(:params) { super().merge(gpg_decrypt_pw: 'anscxk7aeu8ystoz1gtuere7zh') }

              it { is_expected.to compile }

              it do
                is_expected.to add_access_config.with_content(
                  <<~ACCESS

                    # checking each parameter
                    SOURCE                      ANY
                    GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                    GPG_DECRYPT_PW              anscxk7aeu8ystoz1gtuere7zh
                    GPG_ALLOW_NO_PW             N
                  ACCESS
                )
              end
            end
          end

          context 'with gpg_allow_no_pw set to true' do
            let(:params) { super().merge(gpg_allow_no_pw: true) }

            it { is_expected.to compile }

            it do
              is_expected.to add_access_config.with_content(
                <<~ACCESS

                  # checking each parameter
                  SOURCE                      ANY
                  GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                  GPG_ALLOW_NO_PW             Y
                ACCESS
              )
            end

            context 'with gpg_require_sig set to true' do
              let(:params) { super().merge(gpg_require_sig: true) }

              it { is_expected.to compile }

              it do
                is_expected.to add_access_config.with_content(
                  <<~ACCESS

                    # checking each parameter
                    SOURCE                      ANY
                    GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                    GPG_ALLOW_NO_PW             Y
                    GPG_REQUIRE_SIG             Y
                  ACCESS
                )
              end
            end

            context 'with gpg_require_sig set to false' do
              let(:params) { super().merge(gpg_require_sig: false) }

              it { is_expected.to compile }

              it do
                is_expected.to add_access_config.with_content(
                  <<~ACCESS

                    # checking each parameter
                    SOURCE                      ANY
                    GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                    GPG_ALLOW_NO_PW             Y
                    GPG_REQUIRE_SIG             N
                  ACCESS
                )
              end
            end

            context 'with gpg_disable_sig set to true' do
              let(:params) { super().merge(gpg_disable_sig: true) }

              it { is_expected.to compile }

              it do
                is_expected.to add_access_config.with_content(
                  <<~ACCESS

                    # checking each parameter
                    SOURCE                      ANY
                    GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                    GPG_ALLOW_NO_PW             Y
                    GPG_DISABLE_SIG             Y
                  ACCESS
                )
              end
            end

            context 'with gpg_disable_sig set to false' do
              let(:params) { super().merge(gpg_disable_sig: false) }

              it { is_expected.to compile }

              it do
                is_expected.to add_access_config.with_content(
                  <<~ACCESS

                    # checking each parameter
                    SOURCE                      ANY
                    GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                    GPG_ALLOW_NO_PW             Y
                    GPG_DISABLE_SIG             N
                  ACCESS
                )
              end
            end

            context 'with gpg_ignore_sig_verify_error set to true' do
              let(:params) { super().merge(gpg_ignore_sig_verify_error: true) }

              it { is_expected.to compile }

              it do
                is_expected.to add_access_config.with_content(
                  <<~ACCESS

                    # checking each parameter
                    SOURCE                      ANY
                    GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                    GPG_ALLOW_NO_PW             Y
                    GPG_IGNORE_SIG_VERIFY_ERROR Y
                  ACCESS
                )
              end
            end

            context 'with gpg_ignore_sig_verify_error set to false' do
              let(:params) { super().merge(gpg_ignore_sig_verify_error: false) }

              it { is_expected.to compile }

              it do
                is_expected.to add_access_config.with_content(
                  <<~ACCESS

                    # checking each parameter
                    SOURCE                      ANY
                    GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                    GPG_ALLOW_NO_PW             Y
                    GPG_IGNORE_SIG_VERIFY_ERROR N
                  ACCESS
                )
              end
            end

            context 'with gpg_remote_id set to 1a952919b7a7bc497f38378092f9241b2aa0945f' do
              let(:params) { super().merge(gpg_remote_id: '1a952919b7a7bc497f38378092f9241b2aa0945f') }

              it { is_expected.to compile }

              it do
                is_expected.to add_access_config.with_content(
                  <<~ACCESS

                    # checking each parameter
                    SOURCE                      ANY
                    GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                    GPG_ALLOW_NO_PW             Y
                    GPG_REMOTE_ID               1a952919b7a7bc497f38378092f9241b2aa0945f
                  ACCESS
                )
              end
            end

            context 'with gpg_fingerprint_id set to e4a8dae22083ab7e0ca16d290cf78d9d66d751c9' do
              let(:params) { super().merge(gpg_fingerprint_id: 'e4a8dae22083ab7e0ca16d290cf78d9d66d751c9') }

              it { is_expected.to compile }

              it do
                is_expected.to add_access_config.with_content(
                  <<~ACCESS

                    # checking each parameter
                    SOURCE                      ANY
                    GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                    GPG_ALLOW_NO_PW             Y
                    GPG_FINGERPRINT_ID          e4a8dae22083ab7e0ca16d290cf78d9d66d751c9
                  ACCESS
                )
              end
            end

            context 'with gpg_home_dir set to /home/cooldude/.gnupg' do
              let(:params) { super().merge(gpg_home_dir: '/home/cooldude/.gnupg') }

              it { is_expected.to compile }

              it do
                is_expected.to add_access_config.with_content(
                  <<~ACCESS

                    # checking each parameter
                    SOURCE                      ANY
                    GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                    GPG_ALLOW_NO_PW             Y
                    GPG_HOME_DIR                /home/cooldude/.gnupg
                  ACCESS
                )
              end
            end

            context 'with gpg_exe set to /usr/local/bin/gpg' do
              let(:params) { super().merge(gpg_exe: '/usr/local/bin/gpg') }

              it { is_expected.to compile }

              it do
                is_expected.to add_access_config.with_content(
                  <<~ACCESS

                    # checking each parameter
                    SOURCE                      ANY
                    GPG_DECRYPT_ID              bcd35d73e538b5b5a53bee711b567de9c5eaa20b
                    GPG_ALLOW_NO_PW             Y
                    GPG_EXE                     /usr/local/bin/gpg
                  ACCESS
                )
              end
            end
          end
        end
      end
    end
  end
end
