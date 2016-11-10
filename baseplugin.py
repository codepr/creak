#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014-2016 Andrea Baldan
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

import sys
import re
from creak.pluginmanager import Printer

N = '\033[m' # native
R = '\033[31m' # red
G = '\033[32m' # green
O = '\033[33m' # orange
B = '\033[34m' # blue
C = '\033[36m' # cyan
W = '\033[97m' # white
BOLD = '\033[1m'

class Parameters(dict):

    def __init__(self, *args, **kwargs):
        super(Parameters, self).__init__(*args, **kwargs)

    def __setitem__(self, key, value):
        super(Parameters, self).__setitem__(key, value)

    def __delitem__(self, key):
        super(Parameters, self).__delitem__(key)

    def set_values(self, **kwargs):
        """ Sets dynamic size parameters using a kwargs """
        for arg in kwargs:
            self.__setitem__(arg, kwargs[arg])

class BasePlugin(Printer):

    def __init__(self, args):
        self._plugin_name = args
        self.root = False
        self.required_params = Parameters()
        self.info = {}

    def _set_required_params(self, **kwargs):
        self.required_params.set_values(**kwargs)

    def _set_info(self, **kwargs):
        self.info = kwargs

    def _set_root(self, root):
        self.root = root

    def print_info(self):
        """
        Dispaly formatted informations of the plugin, like author, description
        and accepted parameters, either optional or mandatory
        """
        self.print_output('{}General infos:{}\n'.format(BOLD, N))
        for field in sorted(self.info):
            print(' {}{}{}: {}'.format(BOLD, field, N, self.info[field]))
        print('')
        self.print_output('{}Parameters{}\n'.format(BOLD, N))
        for param in sorted(self.required_params):
            required = 'optional'
            if self.required_params[param] is True:
                required = 'required'
            print(' {}{:.<12}{}{:.>15}{}{}'.format(BOLD, param, N, W, required, N))
        print('')

    def init_plugin(self):
        """
        Initialization settings, like meta data and description of the plugin,
        required parameters, required permissions etc.
        """
        raise NotImplementedError('not implemented')

    def run(self):
        """ Here the code of the plugin """
        raise NotImplementedError('not implemented')
