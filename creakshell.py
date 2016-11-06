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
import sys
import threading
from cmd import Cmd
from creak.pluginmanager import PluginManager
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

class CreakShell(PluginManager, Cmd):

    def __init__(self):
        super(CreakShell, self).__init__(sys.path[0])
        Cmd.__init__(self)
        self._prompt_template = W + '[%s::%s] > ' + N
        self.prompt = self._prompt_template % ('creak', 'base')

    def emptyline(self):
        # disable binding on return for the last command prompted
        pass

    def default(self, line):
        # default to shell commands, gives access to underlying shell
        self.do_shell(line)

    def parseline(self, line):
        if '|' in line:
            return 'pipe', line.split('|'), line
        return Cmd.parseline(self, line)

    def do_shell(self, line):
        """ Run a shell command """
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
        """ Loads specified plugin """
        self._params = {}
        if not args:
            return
        # finds any plugins that contain args
        plugins = [args] if args in self._loaded_plugins else [x for x in self._loaded_plugins if args in x]
        # notify the user if none or multiple plugins are found
        if len(plugins) != 1:
            if not plugins:
                self.print_error('Invalid plugin name.')
            else:
                self.print_output('Multiple plugins match \'%s\'.' % args)
            return
        # load the plugin
        plug_dispname = plugins[0]
        plugin = self._loaded_plugins[plug_dispname]
        plugin.init_plugin()
        self._current = plugin
        self.prompt = self._prompt_template % (self.prompt[6:11], plug_dispname.split('/')[-1])

    def do_set(self, args):
        """
        Sets plugin parameters, accept one or more parameters in two different
        forms:
        - set param1 value1 param2 value2 etc..
        - set param1=value1 param2=value2 etc..
        """
        if args:
            params = args.split()
            if any('=' in param for param in params):
                list_of_paramlist = [param.split('=') for param in params]
                params = [param for sublist in list_of_paramlist for param in
                          sublist]
            names, values = params[0::2], params[1::2]
            # TODO: must handle debug parameter
            if self._current:
                for (name, value) in zip(names, values):
                    if name in self._current.required_params:
                        self._params[name] = value
                        print('%s => %s' % (name.upper(), value))
                    else:
                        self.print_error('Invalid parameter.')

    def do_unset(self, args):
        """ Unsets a plugin parameter """
        if args in self._params:
            self._params.pop(args)

    def do_spoofmac(self, args):
        """
        Change the MAC address fetching a prefix from a remote list, or by
        generating a total random one
        """
        macspoof = self._loaded_plugins['mitm/macspoof']
        if args:
            params = {}
            for arg in args.split():
                params[arg.split('=')[0]] = arg.split('=')[1]
            if 'dev' not in params:
                params['dev'] = self._base_params['dev']
            if 'dev_brand' not in params:
                params['dev_brand'] = self._base_params['dev_brand']
            macspoof.run(params)
        else:
            macspoof.run({'dev': self._base_params['dev']})

    def do_run(self, args):
        """
        Validates set parameters, and fallback with auto-detected ones those
        which can be used in place of each other, and finally runs the plugin
        """
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

    def do_plugrun(self, args):
        """
        Load and run a plugin directly by accepting parameters, equals to
        load <plugin>
        set [params values]
        run
        """
        params = args.split()
        self.do_load(params[0])
        params = params[1:]
        pairs = [' '.join(x) for x in zip(params[0::2], params[1::2])]
        for pair in pairs:
            self.do_set(pair)
        self.do_run(self._params)

    def do_recap(self, args):
        """ Display all params set for the current plugin """
        if self._current:
            required_params = self._current.required_params
            print('')
            self.print_output('{}Recap:{}\n'.format(BOLD, N))
            for field in sorted(required_params):
                required = 'optional'
                if required_params[field]:
                    required = 'required'
                if field in  self._params:
                    print(' {:<13} => {:>10} ({})'.format(field.upper(), self._params[field], required))
                else:
                    print(' {:<13} => {:>10} ({})'.format(field.upper(),
                                                          'UNSET', required))
            print('')

    def do_showinfo(self, args):
        """
        Display framework informations or, if in a plugin context, display
        plugin informations, like author, description and parameters accepted
        """
        print('')
        self.print_output('{}Running threads:{} {}'.format(BOLD, N,
                                                           len(threading.enumerate())))
        if self._current:
            self._current.print_info()
        else:
            for field in sorted(self._fwk_info):
                self.print_output('{}{}:{} {}'.format(BOLD, field, N, self._fwk_info[field]))
            print('')

    def do_showplugins(self, args):
        """ List all loaded plugins and informations of them """
        print('')
        self.print_output('Loaded plugins:\n')
        for category in sorted(self._loaded_category):
            if category != 'disabled':
                print(' + {}{}({}){}'.format(G, category, len(self._loaded_category[category]), N))
            else:
                print(' - {}{}({}){}'.format(R, category, len(self._loaded_category[category]), N))
            for plugin in self._loaded_category[category]:
                if category != 'disabled':
                    print('     + {}{}{}'.format(G, plugin, N))
                else:
                    print('     - {}{}{}'.format(R, plugin, N))
            print('')

    def do_clean(self, args):
        """ Clean up all set params, if in a plugin context remove the context """
        self._params = {}
        self._current = None

    def do_quit(self, args):
        """ Quit the application """
        print('Quitting..')
        raise SystemExit

    do_use = do_load
    do_params = do_recap
    do_exit = do_quit
    do_q = do_quit

if __name__ == '__main__':
    CREAK_PROMPT = CreakShell()
    CREAK_PROMPT.init_framework()
    CREAK_PROMPT.cmdloop()
