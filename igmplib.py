# another igmp library

import logging
import struct

from ryu.base import app_manager
from ryu.controller import event
from ryu.controller import ofp_event

from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import DEAD_DISPATCHER

from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_0

from ryu.lib import addrconv
from ryu.lib import hub

from ryu.lib.packet import igmp
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4

from ryu.app.ofctl.api import get_datapath
# {{{
class EventPacketIn(event.EventBase):
    """除去IGMP的PacketIn事件类"""
    def __init__(self, msg):
        """initialization."""
        super(EventPacketIn, self).__init__()
        self.msg = msg

MG_GROUP_ADDED = 1
MG_MEMBER_CHANGED = 2
MG_GROUP_REMOVED = 3


class EventMulticastGroupStateChanged(event.EventBase):
    """一个通知多播组状态改变的事件类"""
    def __init__(self, reason, address, src, dsts):
        """
        ========= =====================================================
        Attribute Description
        ========= =====================================================
        reason    why the event occurs. use one of MG_*.
        address   a multicast group address.
        src       a port number in which a querier exists.
        dsts      a list of port numbers in which the members exist.
        ========= =====================================================
        """
        super(EventMulticastGroupStateChanged, self).__init__()
        self.reason = reason
        self.address = address
        self.src = src
        self.dsts = dsts
# }}}
# {{{
class IgmpLib(app_manager.RyuApp):
    def __init__(self):
        super(IgmpLib, self).__init__()
        self.name = 'igmplib'
        self.logger = logging.getLogger(self.name)
        self._topo_builder = TopoBuilder()

    def set_topology(self, topo):
        self._topo_builder.set_topo(topo)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_hander(self, evt):
        msg = evt.msg

        #  self.logger.info("Packet in")

        req_pkt = packet.Packet(msg.data)
        req_igmp = req_pkt.get_protocol(igmp.igmp)
        if req_igmp:
            self._topo_builder.packet_in_handler(req_igmp, msg)
        else:
            self.send_event_to_observers(EventPacketIn(msg))


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """learn datapath.."""
        datapath = ev.msg.datapath

        dpid = datapath.id
        self._topo_builder._dpid_to_datapath[dpid] = datapath
        self.logger.info("learn dpid: %d", dpid)
        if len(self._topo_builder._dpid_to_datapath) == len(self._topo_builder.switches):
            self._topo_builder.setup_entry_igmp()
            self._topo_builder.setup_entry_rp_to_all()
            self._topo_builder.start_loop(datapath)

# }}}
# class IgmpBase{{{
class IgmpBase(object):
    """IGMP abstract class library."""

    # -------------------------------------------------------------------
    # PUBLIC METHODS
    # -------------------------------------------------------------------
    def __init__(self):
        pass

    def _do_packet_out(self, datapath, data, in_port, actions):
        """send a packet."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            data=data, in_port=in_port, actions=actions)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
                datapath=datapath, command=ofproto.OFPFC_DELETE,
                priority=priority,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                match=match)
        datapath.send_msg(mod)

    # -------------------------------------------------------------------
    # PROTECTED METHODS ( OTHERS )
    # -------------------------------------------------------------------
    def _ipv4_text_to_int(self, ip_text):
        """convert ip v4 string to integer."""
        if ip_text is None:
            return None
        assert isinstance(ip_text, str)
        return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]
# }}}

class TopoBuilder(IgmpBase):
    def __init__(self, *args, **kargs):
        super().__init__()
        self.name = 'TopoBuilder'
        self.logger = logging.getLogger(self.name)

        # or, RP
        self._querier = None
        self._querier_thread = None

        self.switches = {}
        self.pair_map = {}

        self.mcast = {}

        # get datapath by dpid
        self._dpid_to_datapath = {}

# setup {{{
    def set_topo(self, topo):
        """setup topology
        """
        self.logger.info('set topo: %s', topo)
        self._set_up_topo(topo)
        self._pick_up_queier(topo)
        self._set_up()
        self.logger.info("swiwtches: %s", self.switches)
        self.logger.info("dpid maps: %s", self._dpid_to_datapath)

    def _set_up_topo(self, topo):
        for dpid, ports in topo.items():
            m = { 'host_ports': set(),
                    'switch_ports': set(),
                    'down_ports': set(),
                    'up_ports': set()
                    }
            for port, pair in ports.items():
                if pair == 'host':
                    m['host_ports'].add(port)
                else:
                    m['switch_ports'].add(port);
                    for p, w in topo.get(pair).items():
                        if w == dpid:
                            # know pair to each switch ports
                            self.pair_map.setdefault((dpid,port,), (pair,p,))

            self.switches.setdefault(dpid, m)

    def _set_up(self):
        level = set([self._querier])
        assert self._querier
        visited = set()
        while level:
            nxt_level = set()
            for dpid in level:
                if dpid in visited:
                    continue
                visited.add(dpid)

                switch = self.switches.get(dpid)
                switch_ports = switch.get('switch_ports')
                down_ports = switch.setdefault('down_ports', set())
                for port in switch_ports:
                    pair_id,pair_port = self.pair_map.get((dpid,port,))
                    if pair_id in visited:
                        continue
                    else:
                        down_ports.add(port)

                    nxt_level.add(pair_id)
                    pair = self.switches.get(pair_id)
                    pair_up_ports = pair.setdefault('up_ports', set())
                    if len(pair_up_ports) == 0:
                        pair_up_ports.add(pair_port)
            level = nxt_level
        return


    def _pick_up_queier(self, topo):
        """pick up a querier from topo"""
        for k,v in self.switches.items():
            self._querier = k
            return
# }}}
    def setup_entry_igmp(self):
        """packin all igmp packets for switches that has a host connect with

        对于每个switch, 对所有的igmp包都packet in
        """
        for switch_dpid in self.switches.keys():
            datapath = self._dpid_to_datapath.get(switch_dpid)
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match=parser.OFPMatch(
                    eth_type=ether.ETH_TYPE_IP,
                    ip_proto=inet.IPPROTO_IGMP)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            self.add_flow(datapath, 65534, match, actions)

        return

    def setup_entry_rp_to_all(self):
        """send from rp to all maybe hosts, for general query

        对于来自RP的IGMP, target为224.0.0.1的IGMP包, 按照给定的路径发送到每个
        host

        要发送general query可以在RP上进行一次flood.
        """
        self.logger.info('build route for General Query')
        for switch_dpid, switch in self.switches.items():
            datapath = self._dpid_to_datapath.get(switch_dpid)
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            for up in switch.get('up_ports'):
                match=parser.OFPMatch(
                        eth_type=ether.ETH_TYPE_IP,
                        in_port=up,
                        ip_proto=inet.IPPROTO_IGMP,
                        ipv4_dst=self._ipv4_text_to_int('224.0.0.1'))

                actions = [parser.OFPActionOutput(port) for port in
                        switch.get('down_ports')]
                actions = actions + [parser.OFPActionOutput(port) for port in
                        switch.get('host_ports')]
                self.add_flow(datapath, 65535, match, actions)

    def setup_entry_any_to_rp_group(self, group):
        """forward all multicast messages to `group` to RP

        将所有的发送到指定组播组的消息转到RP, 供RP分发.
        """
        self.logger.info("build route to RP for group `%s'", group)
        for switch_dpid, switch in self.switches.items():
            datapath = self._dpid_to_datapath.get(switch_dpid)
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match=parser.OFPMatch(
                    eth_type=ether.ETH_TYPE_IP,
                    ipv4_dst=self._ipv4_text_to_int(group))
            up_ports=switch.get('up_ports')
            if not up_ports:
                continue

            assert len(up_ports) == 1
            actions=[parser.OFPActionOutput(port) for port in
                    up_ports]
            # 优先级次于匹配IGMP包, 总没错
            self.add_flow(datapath, 65533, match, actions)

    def destroy_entry_any_to_rp_group(self, group):
        """forward all multicast messages to `group` to RP

        将所有的发送到指定组播组的消息转到RP, 供RP分发.
        """
        self.logger.info("remove group `%s'", group)
        for switch_dpid, switch in self.switches.items():
            datapath = self._dpid_to_datapath.get(switch_dpid)
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match=parser.OFPMatch(
                    eth_type=ether.ETH_TYPE_IP,
                    ipv4_dst=self._ipv4_text_to_int(group))
            up_ports=switch.get('up_ports')
            if not up_ports:
                continue

            assert len(up_ports) == 1
            # 优先级次于匹配IGMP包, 总没错
            self.del_flow(datapath, 65533, match)

    def _update_group_dpid(self, group, dpid):
        mgroup = self.mcast.setdefault(group, {})
        entries = mgroup.setdefault('entries', {})
        joined_ports = entries.setdefault(dpid, set())

        datapath = self._dpid_to_datapath.get(dpid)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ipv4_dst=self._ipv4_text_to_int(group))
        self.del_flow(datapath, 65534, match)
        if not joined_ports:
            return

        switch = self.switches.get(dpid)
        up_ports = switch.get('up_ports')
        if dpid == self._querier:
            match = parser.OFPMatch(
                    eth_type=ether.ETH_TYPE_IP,
                    ipv4_dst=self._ipv4_text_to_int(group))
            actions = [parser.OFPActionOutput(port) for port in joined_ports]
            actions = actions + [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
            self.add_flow(datapath, 65534, match, actions)
            return

        for port in up_ports:
            match = parser.OFPMatch(
                    eth_type=ether.ETH_TYPE_IP,
                    in_port=port,
                    ipv4_dst=self._ipv4_text_to_int(group))
            actions = [parser.OFPActionOutput(port) for port in joined_ports]
            self.add_flow(datapath, 65534, match, actions)
        return

    def join_group(self, group, dpid, port_no):
        switch = self.switches.get(dpid)
        self._join_group_port(group, dpid, port_no)
        self._join_group_dpid(group, dpid)


    def _join_group_port(self, group, dpid, port_no):
        """add a flow entry
        """
        self.logger.info("join group port: %s, %d, %d", group, dpid, port_no)
        mgroup = self.mcast.setdefault(group, {})
        entries = mgroup.setdefault('entries', {})
        joined_ports = entries.setdefault(dpid, set())
        if port_no in joined_ports:
            return
        joined_ports.add(port_no)
        self._update_group_dpid(group, dpid)

    def _join_group_dpid(self, group, dpid):
        self.logger.info("join group dpid: %s, %d", group, dpid)
        mgroup = self.mcast.setdefault(group, {})
        joined_switches = mgroup.setdefault('joined_switches', set())
        if dpid in joined_switches:
            return
        if dpid == self._querier:
            self.setup_entry_any_to_rp_group(group)
            joined_switches.add(dpid)
            return
        # normal switch
        switch = self.switches.get(dpid)
        up_ports = switch.get('up_ports')
        for port in up_ports:
            pair_id, pair_port = self.pair_map.get((dpid, port,))
            self.join_group(group, pair_id, pair_port)
        joined_switches.add(dpid)

    def leave_group(self, group, dpid, port_no):
        if not self.mcast.get(group):
            return
        self._leave_group_port(group, dpid, port_no)

    def _leave_group_port(self, group, dpid, port_no):
        mgroup = self.mcast.setdefault(group, {})
        entries = mgroup.setdefault('entries', {})
        joined_ports = entries.setdefault(dpid, set())

        if port_no in joined_ports:
            joined_ports.remove(port_no)
            self._update_group_dpid(group, dpid)

        if not joined_ports:
            self._leave_group_dpid(group, dpid)
            return

    def _leave_group_dpid(self, group, dpid):
        mgroup = self.mcast.setdefault(group, {})
        entries = mgroup.setdefault('entries', {})
        joined_ports = entries.setdefault(dpid, set())
        joined_switches = mgroup.setdefault('joined_switches', set())
        self.logger.info("mgroup: %s", mgroup)
        if dpid not in joined_switches:
            return
        if joined_ports:
            return

        self.logger.info("remove switch %d from group %s", dpid, group)

        switch = self.switches.get(dpid)
        up_ports = switch.get('up_ports')
        for port in up_ports:
            pair_id, pair_port = self.pair_map.get((dpid, port,))
            self.leave_group(group, pair_id, pair_port)
        joined_switches.remove(dpid)

        if dpid == self._querier:
            self.destroy_entry_any_to_rp_group(group)
            del self.mcast[group]
            return

    def _do_report(self, report, in_port, msg):
        self.join_group(report.address, msg.datapath.id, in_port)

    def _do_leave(self, report, in_port, msg):
        self.leave_group(report.address, msg.datapath.id, in_port)

    def packet_in_handler(self, req_igmp, msg):
        """
        """
        self.logger.info("packin")
        ofproto = msg.datapath.ofproto
        if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            in_port = msg.in_port
        else:
            in_port = msg.match['in_port']

        if igmp.IGMP_TYPE_QUERY == req_igmp.msgtype:
            self.logger.info("Query? who did that ?")
        if (igmp.IGMP_TYPE_REPORT_V1 == req_igmp.msgtype or
                igmp.IGMP_TYPE_REPORT_V2 == req_igmp.msgtype):
            self._do_report(req_igmp, in_port, msg)
        elif igmp.IGMP_TYPE_LEAVE == req_igmp.msgtype:
            self._do_leave(req_igmp, in_port, msg)
        elif req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V3:
            for record in req_igmp.records:
                self._do_report(record, in_port, msg)
        else:
            self.logger.info("unknown igmp request from port [%d]", in_port)

    def start_loop(self, datapath):
        """start QUERY thread."""
        self._querier_thread = hub.spawn(self._send_query)
        self.logger.info("started a querier.")

    def stop_loop(self):
        """stop QUERY thread."""
        hub.kill(self._querier_thread)
        self._querier_thread = None
        self.logger.info("stopped a querier.")


    def _send_query(self):
        """ send a QUERY message periodically."""
        timeout = 60
        datapath = self._dpid_to_datapath.get(self._querier)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if ofproto_v1_0.OFP_VERSION == ofproto.OFP_VERSION:
            send_port = ofproto.OFPP_NONE
        else:
            send_port = ofproto.OFPP_ANY

        # create a general query.
        res_igmp = igmp.igmp(
            msgtype=igmp.IGMP_TYPE_QUERY,
            maxresp=igmp.QUERY_RESPONSE_INTERVAL * 10,
            csum=0,
            address='0.0.0.0')
        res_ipv4 = ipv4.ipv4(
            total_length=len(ipv4.ipv4()) + len(res_igmp),
            proto=inet.IPPROTO_IGMP, ttl=1,
            src='0.0.0.0',
            dst=igmp.MULTICAST_IP_ALL_HOST)
        res_ether = ethernet.ethernet(
            dst=igmp.MULTICAST_MAC_ALL_HOST,
            src=datapath.ports[ofproto.OFPP_LOCAL].hw_addr,
            ethertype=ether.ETH_TYPE_IP)
        res_pkt = packet.Packet()
        res_pkt.add_protocol(res_ether)
        res_pkt.add_protocol(res_ipv4)
        res_pkt.add_protocol(res_igmp)
        res_pkt.serialize()

        flood = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        while True:
            # send a general query to the host that sent this message.
            self._do_packet_out(
                datapath, res_pkt.data, send_port, flood)
            hub.sleep(igmp.QUERY_RESPONSE_INTERVAL)
            rest_time = timeout - igmp.QUERY_RESPONSE_INTERVAL
            hub.sleep(rest_time)
