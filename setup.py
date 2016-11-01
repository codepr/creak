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

"""
Deny navigation and download capabilities of a target host in the local network
"""
from distutils.core import setup

if __name__ == '__main__':
    setup(
        name='creak',
        version='1.0.3',
        description=__doc__,
        long_description=__doc__,
        author='Andrea Giacomo Baldan',
        author_email='a.g.baldan@gmail.com',
        url='https://github.com/codepr',
        include_package_data=True,
        install_requires=[
            'pypcap',
            'dpkt',
            'dnet',
            'scapy'
        ],
        scripts=[
            'creak.py',
        ],
        license='GPL'
    )
