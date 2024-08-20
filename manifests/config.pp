# Copyright (c) 2024 The Regents of the University of Michigan.
# All Rights Reserved. Licensed according to the terms of the Revised
# BSD License. See LICENSE.txt for details.

# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include fwknop::config
class fwknop::config {
  $pcap_intf = $facts['networking']['primary']

  file { '/etc/fwknop':
    ensure => 'directory',
  }

  file { '/etc/fwknop/fwknopd.conf':
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => template('fwknop/fwknopd.conf.erb'),
  }

  concat { '/etc/fwknop/access.conf':
    owner => 'root',
    group => 'root',
    mode  => '0600',
  }

  concat::fragment { '000 fwknop access header':
    target  => '/etc/fwknop/access.conf',
    order   => '000',
    content => "# Managed by puppet.\n",
  }
}
