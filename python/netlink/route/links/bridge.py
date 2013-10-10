#
# Copyright (c) 2013 Nicolas PLANEL <nicolas.planel@enovance.com>
#

"""BRIDGE network link

"""

from __future__ import absolute_import

from ... import core as netlink
from ..  import capi as capi

class BRIDGELink(object):
    def __init__(self, link):
        self._link = link
        self._has_ext_info = capi.rtnl_link_bridge_has_ext_info(self._link)
        self._port_state_values = ['disabled','listening','learning','forwarding','blocking']

    def bridge_assert_ext_info(self):
        if self._has_ext_info == False:
            print """
            Please update your kernel to be able to call this method.
            Your current kernel bridge version is too old to support this extention.
            """
            raise RuntimeWarning()

    def port_state2str(self, state):
        return self._port_state_values[state]

    def str2port_state(self, str):
        for value, port in enumerate(self._port_state_values):
            if str.lower() == port:
                return value
        raise ValueError()

    @property
    @netlink.nlattr(type=int)
    def port_state(self):
        """bridge state :
        %s
        """ % (self.port_state)
        return capi.rtnl_link_bridge_get_state(self._link)

    @port_state.setter
    def port_state(self, state):
        capi.rtnl_link_bridge_set_state(self._link, int(state))

    @property
    @netlink.nlattr(type=int)
    def priority(self):
        """bridge prio
        """
        bridge_assert_ext_info()
        return capi.rtnl_link_bridge_get_prio(self._link)

    @priority.setter
    def priority(self, prio):
        bridge_assert_ext_info()
        if prio < 0 or prio >= 2**16:
            raise ValueError()
        capi.rtnl_link_bridge_set_prio(self._link, int(prio))

    @property
    @netlink.nlattr(type=int)
    def cost(self):
        """bridge prio
        """
        bridge_assert_ext_info()
        return capi.rtnl_link_bridge_get_cost(self._link)

    @cost.setter
    def cost(self, cost):
        bridge_assert_ext_info()
        if cost < 0 or cost >= 2**32:
            raise ValueError()
        capi.rtnl_link_bridge_set_cost(self._link, int(cost))

    def brief(self):
        return 'bridge-has-ext-info {0}'.format(self._has_ext_info)

def init(link):
    link.bridge = BRIDGELink(link._rtnl_link)
    return link.bridge
