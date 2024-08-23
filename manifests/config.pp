# Copyright (c) 2024 The Regents of the University of Michigan.
# All Rights Reserved. Licensed according to the terms of the Revised
# BSD License. See LICENSE.txt for details.

# @summary
#   This class manages fwknopd.conf and the concat resource for
#   access.conf.
#
# @api private
#
class fwknop::config {
  $pcap_intf = $fwknop::pcap_intf ? {
    undef   => $facts['networking']['primary'],
    default => $fwknop::pcap_intf,
  }

  $pcap_filter = $fwknop::pcap_filter ? {
    Sensitive => $fwknop::pcap_filter.unwrap,
    default   => $fwknop::pcap_filter,
  }

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
