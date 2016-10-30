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

from cmd import Cmd
import os
import re
import sys
import imp
import traceback

N = '\033[m' # native
R = '\033[31m' # red
G = '\033[32m' # green
O = '\033[33m' # orange
B = '\033[34m' # blue

class Parameters(dict):

    def __init__(self, *args, **kwargs):
        super(Parameters, self).__init__(*args, **kwargs)

    def __setitem__(self, key, value):
        super(Parameters, self).__setitem__(key, value)

    def __delitem__(self, key):
        super(Parameters, self).__delitem__(key)

    def set_values(self, **kwargs):
        for arg in kwargs:
            self.__setitem__(arg, kwargs[arg])

class CreakFramework(Cmd):

    def __init__(self, args):
        Cmd.__init__(self)
        self.app_path = sys.path[0]
        self._loaded_plugins = {}
        self._plugin_name = args
        self.ruler = '-'
        self.spacer = '  '
        self._prompt_template = '%s::%s > '
        self.time_format = '%Y-%m-%d %H:%M:%S'
        self.required_params = Parameters()
        self.params = {}
        self.doc_header = 'Commands (type [help|?] <topic>):'
        self.rpc_cache = []
        self._exit = 0
        self._global_options = {'debug': True}

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
            self.error('Plugin \'%s\' disabled. Dependency required: \'%s\'' % (plug_dispname, ex))
        except:
            # notify the user of errors
            self.print_exception()
            self.error('Plugin \'%s\' disabled.' % (plug_dispname))

        # remove the module from the framework's loaded modules
        self._loaded_plugins.pop(plug_dispname, None)
        return False

    def _load_plugins(self):
        self.loaded_category = {}
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
                        if not plug_category in self.loaded_category:
                            self.loaded_category[plug_category] = 0

                        self.loaded_category[plug_category] += 1

    def _set_required_params(self, **kwargs):
        self.required_params.set_values(**kwargs)

    def _validate_params(self):
        for param in self.required_params:
            # if value type is bool or int, then we know the options is set
            # if not type(self.options[option]) in [bool, int]:
            if self.required_params[param] is True and param not in self.params:
                print('Value required for mandatory \'%s\' parameter.' % (param.upper()))
                return False
        return True

    def init_framework(self):
        self._load_plugins()
        self.prompt = self._prompt_template % ('creak', 'default')
        print("Loaded %s plugins " % len(self._loaded_plugins))
        return True

    def default(self, line):
        self.do_shell(line)

    def postcmd(self, stop, line):
        if hasattr(self, 'output') and self.output:
            print(self.output)
            self.output = None

        return stop

    def parseline(self, line):
        if '|' in line:
            return 'pipe', line.split('|'), line

        return Cmd.parseline(self, line)

    def print_exception(self, line=''):
        if self._global_options['debug']:
            traceback.print_exc()
        self.error(line)

    def error(self, line):
        '''Formats and presents errors.'''
        if not re.search('[.,;!?]$', line):
            line += '.'
        line = line[:1].upper() + line[1:]
        print('%s[!] %s%s' % (R, line, N))

    def print_output(self, line):
        '''Formats and presents normal output.'''
        print('%s[*]%s %s' % (B, N, line))

    def do_shell(self, line):
        "Run a shell command"
        output = os.popen(line).read()
        self.output = output

    def do_pipe(self, args):
        buffer = None
        for arg in args:
            s = arg
            if buffer:
                # This command just adds the output of a previous command as the last argument
                s += ' ' + buffer

            self.onecmd(s)
            buffer = self.output

    def do_load(self, args):
        '''Loads specified module'''
        self.params = {}
        if not args:
            return
        # finds any plugins that contain args
        plugins = [args] if args in self._loaded_plugins else [x for x in self._loaded_plugins if args in x]
        # notify the user if none or multiple plugins are found
        if len(plugins) != 1:
            if not plugins:
                self.error('Invalid module name.')
            else:
                self.print_output('Multiple plugins match \'%s\'.' % args)
            return
        # load the module
        plug_dispname = plugins[0]
        # loop to support reload logic
        while True:
            y = self._loaded_plugins[plug_dispname]
            y.init_plugin()
            # send analytics information
            plug_loadpath = os.path.abspath(sys.modules[y.__module__].__file__)
            # begin a command loop
            y.prompt = self._prompt_template % (self.prompt[:-12], plug_dispname.split('/')[-1])
            try:
                y.cmdloop()
            except KeyboardInterrupt:
                print('')
            if y._exit == 1:
                return True
            break

    def do_set(self, args):
        '''Sets module options'''
        params = args.split()
        name = params[0].lower()
        if name in self.required_params:
            value = ' '.join(params[1:])
            self.params[name] = value
            print('%s => %s' % (name.upper(), value))
        else:
            self.error('Invalid parameter.')

    def do_unset(self, args):
        '''Unsets module params'''
        self.do_set('%s %s' % (args, 'None'))

    def do_run(self, args):
        '''Runs the module'''
        try:
            self._summary_counts = {}
            is_valid = self._validate_params()
            if is_valid is True:
                self.run(self.params)
            else:
                return
        except KeyboardInterrupt:
            print('')
        except Exception:
            self.print_exception()

    def do_back(self, args):
        '''Exits the current context'''
        self.params = {}
        return True

    def do_quit(self, args):
        print('Quitting..')
        raise SystemExit

if __name__ == '__main__':
    prompt = CreakFramework('CreakShell')
    prompt.init_framework()
    prompt.cmdloop('Starting prompt...')