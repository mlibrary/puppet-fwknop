# Copyright (c) 2024 The Regents of the University of Michigan.
# All Rights Reserved. Licensed according to the terms of the Revised
# BSD License. See LICENSE.txt for details.

# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include fwknop
class fwknop {
  contain fwknop::install
  contain fwknop::config
  contain fwknop::service

  Class['fwknop::install'] -> Class['fwknop::config'] ~> Class['fwknop::service']
}
