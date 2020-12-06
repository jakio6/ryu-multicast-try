# clone ryu book里的switching hub. 熟悉一下, 尽量少看原来代码吧.

import logging

# 首先, 需要哪些库? 不看具体的代码. 不看ryu book. 当然OpenFlow那部分可以当作参
# 考.
from ryu.base import app_manager

# ryu.controller.controller : the main component of OpenFlow controller.
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER # dispatcher
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls # listing for given event
from ryu.ofproto import ofproto_v1_3 # open flow protocol

#  from ryu.topology import event, switches
#  from ryu.topology.api import get_switch, get_link

from igmplib import IgmpLib
from igmplib import EventPacketIn

from ryu.ofproto import inet
from ryu.ofproto import ether

import ryu.app.ofctl.api as ofctl_api

from json import load

LOG = logging.getLogger(__name__)

class L2Switch(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
            'migmplib': IgmpLib,
            }

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs);
        #  self.topo = *kwargs['topology']
        #  self.topo = {
                #  1: {1: 2, 2: 3},
                #  2: {3: 1, 1: 'host', 2: 'host'},
                #  3: {3: 1, 1: 'host', 2: 'host'},
                #  }
        topo = {}
        with open('topo.json') as f:
            _topo = load(f)
            assert _topo
            for k, v in _topo.items():
                sw = topo.setdefault(int(k), {})
                for kk, vv in v.items():
                    sw.setdefault(int(kk), vv)


        self._igmp = kwargs['migmplib']
        self._dpid_to_datapath = {}
        self._igmp.set_topology(topo)

    def manual_flood(self, dp, data):
        """
        send a message to all ports of a datapath
        """
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        buffer_id = ofp.OFP_NO_BUFFER # None
        in_port =  ofp.OFPP_CONTROLLER # None

        # flooding
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        req = ofp_parser.OFPPacketOut(dp, buffer_id, in_port, actions, data)

        dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        LOG.info("Switch feather: %d", datapath.id)
        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(EventPacketIn)
    def packet_in_handler(self, ev):
        msg = ev.msg # message carried with event.. see related pagse for its content
        datapath = msg.datapath
        #  reason = msg.reason
        data = msg.data
        LOG.debug('packet in')

        #  self.manual_flood(datapath, data)
