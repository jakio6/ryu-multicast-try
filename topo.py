#!/usr/bin/env python

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.topolib import TreeTopo
from mininet.topolib import TorusTopo

from functools import partial

from json import dump

def main():
    t = TorusTopo(3,3)
    prot="OpenFlow13"
    net = Mininet(controller=RemoteController)
    net.buildFromTopo(t)
    #  c0 = net.addController('c0', ip='127.0.0.1', port=6633)

    topo = {}
    for link in t.links():
        info = t.linkInfo(link[0], link[1])
        n1 = info['node1']
        n2 = info['node2']
        p1 = info['port1']
        p2 = info['port2']

        t1 = int(net.getNodeByName(n1).dpid, 16) if t.isSwitch(n1) else 'host'
        t2 = int(net.getNodeByName(n2).dpid, 16) if t.isSwitch(n2) else 'host'

        if t1 != 'host':
            m1 = topo.setdefault(t1, {})
            m1[p1] = t2
        if t2 != 'host':
            m1 = topo.setdefault(t2, {})
            m1[p2] = t1

    hosts = t.hosts()
    switches = t.switches()
    def make_igmp_host(ho, hn):
        ho.cmd('route add -net 224.0.0.0 netmask 224.0.0.0 '+hn+'-eth0')
    for hn in hosts:
        ho = net.get(hn)
        make_igmp_host(ho, hn)
    for sn in switches:
        net.get(sn).cmd('ovs-vsctl set bridge '+sn+'protocols=OpenFlow13')

    with open('topo.json', 'w') as f:
        dump(topo, f)

    net.build()
    net.start()
    CLI(net)
    net.stop()

if __name__ == "__main__":
    main()
