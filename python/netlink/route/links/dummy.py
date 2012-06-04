#
# Copyright (c) 2011 Thomas Graf <tgraf@suug.ch>
#

"""Dummy

"""
from __future__ import absolute_import

__version__ = "1.0"
__all__ = ['init']


from ... import core as netlink
from ..  import capi as capi
class DummyLink(object):
	def __init__(self, link):
        	self._rtnl_link = link

	def brief(self):
        	return 'dummy'
	
def init(link):
	link.dummy = DummyLink(link._rtnl_link)
        return link.dummy
