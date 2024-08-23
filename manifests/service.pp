# Copyright (c) 2024 The Regents of the University of Michigan.
# All Rights Reserved. Licensed according to the terms of the Revised
# BSD License. See LICENSE.txt for details.

# @summary
#   This class manages the service resource for fwknop-server.
#
# @api private
#
class fwknop::service {
  service { 'fwknop-server': }
}
