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

import os
import re
import sys
import imp
import traceback
import subprocess
import creak.utils as utils
from creak.utils import B, N, R, G, W, U, O, BOLD

PLUGINS_DIR = '/plugins/'

class Printer(object):

    """ Utility class, display different message categories in a custom way """

    @staticmethod
    def print_exception(line=''):
        """ Display formatted exceptions """
        traceback.print_exc()
        line = ' '.join([x for x in [traceback.format_exc().strip().splitlines()[-1], line] if x])
        Printer.print_error(line)

    @staticmethod
    def print_error(line):
        """ Display fomatted errors """
        if not re.search('[.,;!?]$', line):
            line += '.'
        line = line[:1].upper() + line[1:]
        print('{}{}[!] {}{}'.format(U, R, line, N))

    @staticmethod
    def print_output(line):
        """ Display formatted output """
        print('{}[*]{} {}'.format(B, N, line))

class PluginManager(Printer):

    """ Base class for creak framework, here all plugin are loaded and managed """

    def __init__(self, path):
        self._app_path = path
        self._loaded_plugins = {}
        self._loaded_categories = {}
        self._params = {}
        self._history = []
        self._current = None
        self._fwk_info = {'Author': 'codep', 'Version': '1.6.0'}
        self._base_params = {}

    def _load_plugin(self, dirpath, filename):
        plug_name = filename.split('.')[0]
        plug_dispname = '/'.join(dirpath.split(PLUGINS_DIR)[-1].split('/') + [plug_name])
        plug_loadname = plug_dispname.replace('/', '_')
        plug_loadpath = os.path.join(dirpath, filename)
        plug_file = open(plug_loadpath)
        try:
            # import the plugin into memory
            imp.load_source(plug_loadname, plug_loadpath, plug_file)
            __import__(plug_loadname)
            # add the plugin to the framework's loaded plugins
            self._loaded_plugins[plug_dispname] = sys.modules[plug_loadname].Plugin(plug_dispname)
            return True
        except ImportError as ex:
            # notify the user of missing dependencies
            self.print_error('Plugin \'%s\' disabled. Dependency required: \'%s\'' % (plug_dispname, ex))
        except:
            # notify the user of errors
            self.print_exception()
            self.print_error('Plugin \'%s\' disabled.' % (plug_dispname))

        # remove the plugin from the framework's loaded plugins
        self._loaded_plugins.pop(plug_dispname, None)
        return False

    def _load_plugins(self):
        self._loaded_categories = {}
        # crawl the plugin directory
        for path in [os.path.join(x, PLUGINS_DIR[1:-1]) for x in (self._app_path,
                                                                  self._app_path)]:
            for dirpath, dirnames, filenames in os.walk(path):
                # remove hidden files and directories
                filenames = [f for f in filenames if f[0] != '.']
                dirnames[:] = [d for d in dirnames if d[0] != '.']
                if len(filenames) > 0:
                    for filename in [f for f in filenames if f.endswith('.py')]:
                        is_loaded = self._load_plugin(dirpath, filename)
                        plug_category = 'disabled'
                        if is_loaded:
                            plug_category = re.search(PLUGINS_DIR + '([^/]*)', dirpath).group(1)
                        # store the resulting category if not already memorized
                        if plug_category not in self._loaded_categories:
                            self._loaded_categories[plug_category] = [filename]
                        # add plugin to the list of his category
                        elif filename not in self._loaded_categories[plug_category]:
                            self._loaded_categories[plug_category].append(filename)

    def _validate_params(self):
        for param in self._current.required_params:
            # fallback parameters not set with auto detected if any
            if self._current.required_params[param] and param not in self._params and param in self._base_params:
                self._params[param] = self._base_params[param]
            elif self._current.required_params[param] and param not in self._params:
                print('Value required for mandatory parameter \'%s\'.' % (param.upper()))
                return False
        return True

    def init_framework(self):
        """
        Init the framework, loading all plugins and setting all class variables,
        trying also to retrieve some basic info from the system
        """
        self._load_plugins()
        self._fwk_info['Loaded plugins'] = len(self._loaded_plugins)
        # print basic banner
        print('')
        print(' {}Creak v1.6.0{}'.format(BOLD, N))
        print(' =======================================\n')
        print(' Author: Andrea Giacomo Baldan')
        print('         a.g.baldan@gmail.com')
        print('         https://github.com/codepr\n')
        print(' ---------------------------------------\n')
        print(' Successfully loaded %s plugins ' % len(self._loaded_plugins))
        print(' Categories:\n')
        print(' ---------------------------------------\n')
        # list loaded plugins
        for category in sorted(self._loaded_categories):
            if category != 'disabled':
                print(' + {}{}({}){}'.format(G, category,
                                             len(self._loaded_categories[category]), N))
            else:
                print(' - {}{}({}){}'.format(R, category,
                                             len(self._loaded_categories[category]), N))
            for plugin in self._loaded_categories[category]:
                if category != 'disabled':
                    print('     + {}{}{}'.format(G, plugin, N))
                else:
                    print('     - {}{}{}'.format(R, plugin, N))
            print('')
        # retrieve common informations with ip r l command
        if os.path.exists("/usr/bin/ip") or os.path.exists("/bin/ip"):
            iprl = subprocess.check_output('ip r l'.split())
            self._base_params['gateway'] = iprl.split('default via')[-1].split()[0]
            self._base_params['dev'] = iprl.split('dev')[-1].split()[0]
            self._base_params['localip'] = iprl.split('src')[-1].split()[0]
            self._base_params['mac_addr'] = utils.get_mac_by_dev(self._base_params['dev'])
            self._base_params['gateway_addr'] = utils.get_mac_by_ip(self._base_params['gateway'])
            self._base_params['dev_brand'] = utils.get_dev_brand().lstrip()
        print('')
        print(' Common informations detected\n')
        print(' ---------------------------------------\n')
        for param in sorted(self._base_params):
            print(' {}{:.<12}{}{:.>15}{}{}'.format(BOLD, param, N, W, self._base_params[param], N))
        if os.getuid() != 0:
            print('\n {}Most of the features of creak requires root privileges,\n'
                  ' please reload the framework using sudo or with root privileges{}'.format(O, N))
        print('')

        return True

