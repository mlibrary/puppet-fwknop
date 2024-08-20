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
              PCAP_INTF #{facts[:networking]['primary']}
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
    end
  end
end
