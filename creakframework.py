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
import shlex
from cmd import Cmd
import creak.utils as utils

N = '\033[m'   # native
R = '\033[31m' # red
G = '\033[32m' # green
O = '\033[33m' # orange
B = '\033[34m' # blue
C = '\033[36m' # cyan
W = '\033[97m' # white
U = '\033[4m'  # underlined
BOLD = '\033[1m'

class Printer(object):

    """ Utility class, display different message categories in a custom way """

    @staticmethod
    def print_exception(line=''):
        """ Display formatted exceptions """
        # if self._global_options['debug']:
        # traceback.print_exc()
        line = ' '.join([x for x in [traceback.format_exc().strip().splitlines()[-1], line] if x])
        Printer.print_error(line)

    @staticmethod
    def print_error(line):
        """ Display fomatted errors """
        if not re.search('[.,;!?]$', line):
            line += '.'
        line = line[:1].upper() + line[1:]
        print('%s%s[!] %s%s' % (U, R, line, N))

    @staticmethod
    def print_output(line):
        """ Display formatted output """
        print('%s[*]%s %s' % (C, N, line))

class CreakFramework(Cmd, Printer):

    """ Base class for creak framework, here all plugin are loaded and managed """

    def __init__(self, args):
        Cmd.__init__(self)
        self.app_path = sys.path[0]
        self._loaded_plugins = {}
        self._loaded_category = {}
        self._prompt_template = W + '[%s::%s] > ' + N
        self._params = {}
        self._current = None
        self._fwk_info = {'author': 'codep', 'version': '1.0'}
        self._base_params = {}

    def _load_plugin(self, dirpath, filename):
        plug_name = filename.split('.')[0]
        plug_dispname = '/'.join(re.split('/plugins/', dirpath)[-1].split('/') + [plug_name])
        plug_loadname = plug_dispname.replace('/', '_')
        plug_loadpath = os.path.join(dirpath, filename)
        plug_file = open(plug_loadpath)
        try:
            # import the module into memory
            imp.load_source(plug_loadname, plug_loadpath, plug_file)
            __import__(plug_loadname)
            # add the module to the framework's loaded modules
            self._loaded_plugins[plug_dispname] = sys.modules[plug_loadname].Plugin(plug_dispname)
            return True
        except ImportError as ex:
            # notify the user of missing dependencies
            self.print_error('Plugin \'%s\' disabled. Dependency required: \'%s\'' % (plug_dispname, ex))
        except:
            # notify the user of errors
            self.print_exception()
            self.print_error('Plugin \'%s\' disabled.' % (plug_dispname))

        # remove the module from the framework's loaded modules
        self._loaded_plugins.pop(plug_dispname, None)
        return False

    def _load_plugins(self):
        self._loaded_category = {}
        # crawl the module directory and build the module tree
        for path in [os.path.join(x, 'plugins') for x in (self.app_path, self.app_path)]:
            for dirpath, dirnames, filenames in os.walk(path):
                # remove hidden files and directories
                filenames = [f for f in filenames if not f[0] == '.']
                dirnames[:] = [d for d in dirnames if not d[0] == '.']
                if len(filenames) > 0:
                    for filename in [f for f in filenames if f.endswith('.py')]:
                        is_loaded = self._load_plugin(dirpath, filename)
                        plug_category = 'disabled'
                        if is_loaded:
                            plug_category = re.search('/plugins/([^/]*)', dirpath).group(1)

                        # store the resulting category statistics
                        if not plug_category in self._loaded_category:
                            self._loaded_category[plug_category] = [filename]
                        elif filename not in self._loaded_category[plug_category]:
                            self._loaded_category[plug_category].append(filename)

    def _validate_params(self):
        for param in self._current.required_params:
            if self._current.required_params[param] is True and param not in self._params and param in self._base_params:
                self._params[param] = self._base_params[param]
            elif self._current.required_params[param] is True and param not in self._params:
                print('Value required for mandatory \'%s\' parameter.' % (param.upper()))
                return False
        return True

    def init_framework(self):
        """
        Init the framework, loading all plugins and setting all class variables,
        trying also to retrieve some basic info from the system
        """
        self._load_plugins()
        self.prompt = self._prompt_template % ('creak', 'base')
        print('')
        print(' Author: Andrea Giacomo Baldan')
        print('         a.g.baldan@gmail.com')
        print('         https://github.com/codepr\n')
        print(' ---------------------------------------\n')
        print(' Successfully loaded %s plugins ' % len(self._loaded_plugins))
        print(' Categories:\n')
        print(' ----------------------------------\n')
        for category in sorted(self._loaded_category):
            if category != 'disabled':
                print(' {}{}({}){}'.format(G, category, len(self._loaded_category[category]), N))
            else:
                print(' {}{}({}){}'.format(R, category, len(self._loaded_category[category]), N))
            for plugin in self._loaded_category[category]:
                if category != 'disabled':
                    print('     + {}{}{}'.format(G, plugin, N))
                else:
                    print('     + {}{}{}'.format(R, plugin, N))
            print('')
        strs = subprocess.check_output(shlex.split('ip r l'))
        gateway = strs.split('default via')[-1].split()[0]
        dev = strs.split('dev')[-1].split()[0]
        localip = strs.split('src')[-1].split()[0]
        mac_addr = utils.get_mac_by_dev(dev)
        gateway_addr = utils.get_mac_by_ip(gateway)
        self._base_params['dev'], self._base_params['gateway'] = dev, gateway
        self._base_params['localip'], self._base_params['gateway_addr'] = localip, gateway_addr
        if mac_addr:
            self._base_params['mac_addr'] = mac_addr
        print('')
        print(' Detected some informations\n')
        print(' ----------------------------------\n')
        for param in sorted(self._base_params):
            print(' {}{:.<12}{}{:.>15}{}{}'.format(BOLD, param, N, W, self._base_params[param], N))
        print('')
        return True

    def emptyline(self):
        pass

    def default(self, line):
        self.do_shell(line)

    def parseline(self, line):
        if '|' in line:
            return 'pipe', line.split('|'), line
        return Cmd.parseline(self, line)

    def do_shell(self, line):
        "Run a shell command"
        output = os.popen(line).read()
        if line == 'ls':
            files = output.split('\n')
            for f in files:
                if os.path.isdir(f):
                    print('{}{}{}{}'.format(BOLD, B, f, N))
                else:
                    print(f)
        else:
            print('\n%s' % output)

    def do_pipe(self, args):
        buffer = None
        for arg in args:
            s = arg
            if buffer:
                # This command just adds the output of a previous command as the last argument
                s += ' ' + buffer

            # self.onecmd(s)
            # buffer = self.output

    def do_load(self, args):
        '''Loads specified module'''
        self._params = {}
        if not args:
            return
        # finds any plugins that contain args
        plugins = [args] if args in self._loaded_plugins else [x for x in self._loaded_plugins if args in x]
        # notify the user if none or multiple plugins are found
        if len(plugins) != 1:
            if not plugins:
                self.print_error('Invalid module name.')
            else:
                self.print_output('Multiple plugins match \'%s\'.' % args)
            return
        # load the module
        plug_dispname = plugins[0]
        # loop to support reload logic
        plugin = self._loaded_plugins[plug_dispname]
        plugin.init_plugin()
        self._current = plugin
        # self.required_params = plugin.required_params
        self.prompt = self._prompt_template % (self.prompt[6:11], plug_dispname.split('/')[-1])

    def do_set(self, args):
        '''Sets module options'''
        params = args.split()
        name = params[0].lower()
        if name in self._current.required_params:
            value = ' '.join(params[1:])
            self._params[name] = value
            print('%s => %s' % (name.upper(), value))
        else:
            self.print_error('Invalid parameter.')

    def do_unset(self, args):
        '''Unsets module params'''
        self.do_set('%s %s' % (args, 'None'))

    def do_run(self, args):
        '''Runs the module'''
        try:
            is_valid = self._validate_params()
            if is_valid:
                if self._current.root and os.geteuid() != 0:
                    self.print_error('Root permissions required')
                    return
                self._current.run(self._params)
            else:
                return
        except KeyboardInterrupt:
            print('')
        except Exception:
            self.print_exception()

    def do_recap(self, args):
        """ Display all params set for the current plugin """
        if self._current:
            required_params = self._current.required_params
            print('')
            print(self._params)
            self.print_output('{}Recap:{}\n'.format(BOLD, N))
            for field in sorted(required_params):
                required = 'optional'
                if required_params[field] is True:
                    required = 'required'
                if field in  self._params:
                    print(' {:<8} => {:>12} ({})'.format(field.upper(), self._params[field], required))
                else:
                    print(' {:<8} => UNSET ({})'.format(field.upper(), required))
            print('')

    def do_showinfo(self, args):
        if self._current:
            self._current.print_info()
        else:
            for field in sorted(self._fwk_info):
                print('{}: {}'.format(field, self._fwk_info[field]))

    def do_clean(self, args):
        """ Clean up all params """
        self._params = {}
        self._current = None

    def do_quit(self, args):
        """ Exit the application """
        print('Quitting..')
        raise SystemExit

    do_use = do_load
    do_params = do_recap
    do_exit = do_quit
    do_q = do_quit

if __name__ == '__main__':
    CREAK_PROMPT = CreakFramework('CreakShell')
    CREAK_PROMPT.init_framework()
    CREAK_PROMPT.cmdloop()
