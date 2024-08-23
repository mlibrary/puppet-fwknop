# Copyright (c) 2024 The Regents of the University of Michigan.
# All Rights Reserved. Licensed according to the terms of the Revised
# BSD License. See LICENSE.txt for details.

# @summary
#   This class manages the package resource for fwknop-server.
#
# @api private
#
class fwknop::install {
  if $fwknop::package_manage {
    package { 'fwknop-server': }
  }
}
