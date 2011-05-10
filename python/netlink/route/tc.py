

#
# Copyright (c) 2011 Thomas Graf <tgraf@suug.ch>
#

__all__ = [
	'TcCache',
	'Tc',
	'QdiscCache',
	'Qdisc']

import socket
import sys
import netlink.core as netlink
import netlink.capi as core_capi
import netlink.route.capi as capi
import netlink.util as util

from netlink.route.link import Link

TC_PACKETS = 0
TC_BYTES = 1
TC_RATE_BPS = 2
TC_RATE_PPS = 3
TC_QLEN = 4
TC_BACKLOG = 5
TC_DROPS = 6
TC_REQUEUES = 7
TC_OVERLIMITS = 9

TC_H_ROOT = 0xFFFFFFFF
TC_H_INGRESS = 0xFFFFFFF1

class Handle(object):
	def __init__(self, val=None):
        	if type(val) is str:
                        val = capi.tc_str2handle(val)
        	elif not val:
                        val = 0

        	self._val = int(val)

	def __int__(self):
        	return self._val

        def __str__(self):
        	return capi.rtnl_tc_handle2str(self._val, 64)[0]

	def isroot(self):
        	return self._val == TC_H_ROOT or self._val == TC_H_INGRESS

###########################################################################
# TC Cache
class TcCache(netlink.Cache):
	"""Cache of traffic control object"""

	def __getitem__(self, key):
        	raise NotImplementedError()

###########################################################################
# Tc Object
class Tc(netlink.Object):
	def __cmp__(self, other):
        	return self.ifindex - other.ifindex

	def isroot(self):
        	return self.parent.isroot()

	#####################################################################
	# ifindex
        @property
        def ifindex(self):
                """interface index"""
                return capi.rtnl_tc_get_ifindex(self._tc)

	@ifindex.setter
        def ifindex(self, value):
                capi.rtnl_tc_set_ifindex(self._tc, int(value))

	#####################################################################
	# link
        @property
        def link(self):
		link = capi.rtnl_tc_get_link(self._tc)
                if not link:
                        return None
                else:
                        return Link._from_capi(link)

        @link.setter
        def link(self, value):
        	capi.rtnl_tc_set_link(self._tc, value._link)

	#####################################################################
	# mtu
        @property
        def mtu(self):
                return capi.rtnl_tc_get_mtu(self._tc)

	@mtu.setter
        def mtu(self, value):
                capi.rtnl_tc_set_mtu(self._tc, int(value))

	#####################################################################
	# mpu
        @property
        def mpu(self):
                return capi.rtnl_tc_get_mpu(self._tc)

	@mpu.setter
        def mpu(self, value):
                capi.rtnl_tc_set_mpu(self._tc, int(value))

	#####################################################################
	# overhead
        @property
        def overhead(self):
                return capi.rtnl_tc_get_overhead(self._tc)

	@overhead.setter
        def overhead(self, value):
                capi.rtnl_tc_set_overhead(self._tc, int(value))

	#####################################################################
	# linktype
        @property
        def linktype(self):
                return capi.rtnl_tc_get_linktype(self._tc)

	@linktype.setter
        def linktype(self, value):
                capi.rtnl_tc_set_linktype(self._tc, int(value))

	#####################################################################
	# handle
        @property
        def handle(self):
                return Handle(capi.rtnl_tc_get_handle(self._tc))

	@handle.setter
        def handle(self, value):
                capi.rtnl_tc_set_handle(self._tc, int(value))

	#####################################################################
	# parent
        @property
        def parent(self):
                return Handle(capi.rtnl_tc_get_parent(self._tc))

	@parent.setter
        def parent(self, value):
                capi.rtnl_tc_set_parent(self._tc, int(value))

	#####################################################################
	# kind
        @property
        def kind(self):
                return capi.rtnl_tc_get_kind(self._tc)

	@kind.setter
        def kind(self, value):
                capi.rtnl_tc_set_kind(self._tc, value)

	def get_stat(self, id):
        	return capi.rtnl_tc_get_stat(self._tc, id)

class TcTree(object):
	def __init__(self, link, sock):
        	self._qdisc_cache = QdiscCache().refill(sock)

	def __getitem__(self, key):
        	pass
#        	if type(key) is int:
#                        link = capi.rtnl_link_get(self._this, key)
#                elif type(key) is str:
#                        link = capi.rtnl_link_get_by_name(self._this, key)
#
#		if qdisc is None:
#                        raise KeyError()
#		else:
#                        return Qdisc._from_capi(capi.qdisc2obj(qdisc))

	


###########################################################################
# Link Cache
class QdiscCache(netlink.Cache):
	"""Cache of qdiscs"""

	def __init__(self, cache=None):
        	if not cache:
                        cache = self._alloc_cache_name("route/qdisc")

                self._c_cache = cache

#	def __getitem__(self, key):
#        	if type(key) is int:
#                        link = capi.rtnl_link_get(self._this, key)
#                elif type(key) is str:
#                        link = capi.rtnl_link_get_by_name(self._this, key)
#
#		if qdisc is None:
#                        raise KeyError()
#		else:
#                        return Qdisc._from_capi(capi.qdisc2obj(qdisc))

	def _new_object(self, obj):
        	return Qdisc(obj)

	def _new_cache(self, cache):
		return QdiscCache(cache=cache)

###########################################################################
# Qdisc Object
class Qdisc(Tc):
	"""Network link"""

	def __init__(self, obj=None):
		self._name = "qdisc"
		self._abbr = "qdisc"

		if not obj:
			self._qdisc = capi.rtnl_qdisc_alloc()
		else:
			self._qdisc = capi.obj2qdisc(obj)

		self._obj = capi.qdisc2obj(self._qdisc)
		self._orig = capi.obj2qdisc(core_capi.nl_object_clone(self._obj))

		Tc.__init__(self)

		netlink.attr('qdisc.handle', fmt=util.handle)
		netlink.attr('qdisc.parent', fmt=util.handle)
		netlink.attr('qdisc.kind', fmt=util.bold)

	def __cmp__(self, other):
		return self.handle - other.handle

	def _new_instance(self, obj):
		if not obj: raise ValueError()
                return Qdisc(obj)

#	#####################################################################
#	# add()
#	def add(self, socket, flags=None):
#        	if not flags:
#                        flags = netlink.NLM_F_CREATE
#
#		ret = capi.rtnl_link_add(socket._sock, self._link, flags)
#		if ret < 0:
#			raise netlink.KernelError(ret)
#
#	#####################################################################
#	# change()
#	def change(self, socket, flags=0):
#		"""Commit changes made to the link object"""
#		if not self._orig:
#			raise NetlinkError("Original link not available")
#        	ret = capi.rtnl_link_change(socket._sock, self._orig, self._link, flags)
#                if ret < 0:
#                        raise netlink.KernelError(ret)
#
#	#####################################################################
#	# delete()
#	def delete(self, socket):
#		"""Attempt to delete this link in the kernel"""
#        	ret = capi.rtnl_link_delete(socket._sock, self._link)
#                if ret < 0:
#                        raise netlink.KernelError(ret)

        @property
        def _dev(self):
        	buf = util.kw('dev') + ' '

                if self.link:
			return buf + util.string(self.link.name)
                else:
			return buf + util.num(self.ifindex)

        @property
        def _parent(self):
        	return util.kw('parent') + ' ' + str(self.parent)

	###################################################################
	#
	# format(details=False, stats=False)
	#
	def format(self, details=False, stats=False):
        	"""Return qdisc as formatted text"""
		fmt = util.BriefFormatter(self)

		buf = fmt.format('qdisc {kind} {handle} {_dev} {_parent}')

		if details:
			fmt = util.DetailFormatter(self)
			buf += fmt.format('\n'\
                          '\t{mtu} {mpu} {overhead}\n')
                	
#		if stats:
#			l = [['Packets', RX_PACKETS, TX_PACKETS],
#			     ['Bytes', RX_BYTES, TX_BYTES],
#			     ['Errors', RX_ERRORS, TX_ERRORS],
#			     ['Dropped', RX_DROPPED, TX_DROPPED],
#			     ['Compressed', RX_COMPRESSED, TX_COMPRESSED],
#			     ['FIFO Errors', RX_FIFO_ERR, TX_FIFO_ERR],
#			     ['Length Errors', RX_LEN_ERR, None],
#			     ['Over Errors', RX_OVER_ERR, None],
#			     ['CRC Errors', RX_CRC_ERR, None],
#			     ['Frame Errors', RX_FRAME_ERR, None],
#			     ['Missed Errors', RX_MISSED_ERR, None],
#			     ['Abort Errors', None, TX_ABORT_ERR],
#			     ['Carrier Errors', None, TX_CARRIER_ERR],
#			     ['Heartbeat Errors', None, TX_HBEAT_ERR],
#			     ['Window Errors', None, TX_WIN_ERR],
#			     ['Collisions', None, COLLISIONS],
#			     ['Multicast', None, MULTICAST],
#			     ['', None, None],
#			     ['Ipv6:', None, None],
#			     ['Packets', IP6_INPKTS, IP6_OUTPKTS],
#			     ['Bytes', IP6_INOCTETS, IP6_OUTOCTETS],
#			     ['Discards', IP6_INDISCARDS, IP6_OUTDISCARDS],
#			     ['Multicast Packets', IP6_INMCASTPKTS, IP6_OUTMCASTPKTS],
#			     ['Multicast Bytes', IP6_INMCASTOCTETS, IP6_OUTMCASTOCTETS],
#			     ['Broadcast Packets', IP6_INBCASTPKTS, IP6_OUTBCASTPKTS],
#			     ['Broadcast Bytes', IP6_INBCASTOCTETS, IP6_OUTBCASTOCTETS],
#			     ['Delivers', IP6_INDELIVERS, None],
#			     ['Forwarded', None, IP6_OUTFORWDATAGRAMS],
#			     ['No Routes', IP6_INNOROUTES, IP6_OUTNOROUTES],
#			     ['Header Errors', IP6_INHDRERRORS, None],
#			     ['Too Big Errors', IP6_INTOOBIGERRORS, None],
#			     ['Address Errors', IP6_INADDRERRORS, None],
#			     ['Unknown Protocol', IP6_INUNKNOWNPROTOS, None],
#			     ['Truncated Packets', IP6_INTRUNCATEDPKTS, None],
#			     ['Reasm Timeouts', IP6_REASMTIMEOUT, None],
#			     ['Reasm Requests', IP6_REASMREQDS, None],
#			     ['Reasm Failures', IP6_REASMFAILS, None],
#			     ['Reasm OK', IP6_REASMOKS, None],
#			     ['Frag Created', None, IP6_FRAGCREATES],
#			     ['Frag Failures', None, IP6_FRAGFAILS],
#			     ['Frag OK', None, IP6_FRAGOKS],
#			     ['', None, None],
#			     ['ICMPv6:', None, None],
#			     ['Messages', ICMP6_INMSGS, ICMP6_OUTMSGS],
#			     ['Errors', ICMP6_INERRORS, ICMP6_OUTERRORS]]
#
#			buf += '\n\t%s%s%s%s\n' % (33 * ' ', util.title('RX'),
#                        			   15 * ' ', util.title('TX'))
#
#			for row in l:
#				row[0] = util.kw(row[0])
#                                row[1] = self.get_stat(row[1]) if row[1] else ''
#                                row[2] = self.get_stat(row[2]) if row[2] else ''
#				buf += '\t{0:27} {1:>16} {2:>16}\n'.format(*row)

		return buf
