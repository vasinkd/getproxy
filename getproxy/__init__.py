# -*- coding: utf-8 -*-

__author__ = """fate0"""
__email__ = 'fate0@fatezero.org'
__version__ = '0.2.3'

import gevent.monkey
gevent.monkey.patch_all()
from .getproxy import GetProxy
