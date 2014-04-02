# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
#Dpendencia! networkx musi byt nainstalovany!
#sudo pip install networkx
import networkx as nx
import json
import random
from webob import Response

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
#from ryu.lib import ofctl_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication


LOG = logging.getLogger('ryu.app.ofctl_rest')

# REST API for "mac tunnels"
#
# Test REST API
# GET /gprs/info/{opt}
# test output on controller console
#
# modify pdp context
# POST /gprs/pdp/{cmd}
#
# accepted cmd arguments are 'add' 'mod' 'del'
# parameters needed for tunnel creation are inserted into body of the request
#
# Example body:
#
#{'start' : '0', 'end' : '4', 'condition' : { 'eth_type' : 0x0800, 'ipv4_src' : '172.16.0.1', 'ipv4_dst' : '172.16.0.2'}, 'mirror' : 'yes'}
#
# start = datapath ID of first forwarder in tunnel
# end = datapath ID of last forwarder in tunnel
# condition = dictionary of supported match rules
#     supperted match fields = eth_type, ipv4_src, ipv4_dst, eth_src, eth_dst
# mirror = if yes then tunnel will be created in backward dirrection too


class node:
  def __init__(self, dpid, port_out):
    self.dpid = dpid
    self.port_out = port_out

class tunnels:
  def __init__(self, TID, condition, nodes):
    self.TID = TID
    self.nodes = nodes
    self.condition = condition


class topology():

    def __init__(self):
        self.StaticGraph=nx.DiGraph()
        self.DynamicGraph=nx.DiGraph()
        
        self.add_link(1,2,2)
        self.add_link(2,3,2)
        self.add_link(3,2,2)
        self.add_link(2,1,1)
        
        #end_linky
        self.add_link(3,4,1)
        self.add_link(4,3,0)        
        self.add_link(1,0,1)
        self.add_link(0,1,0)
        self.reload_topology()
           
    def add_forwarder(self, fwID):
       self.StaticGraph.add_node(fwID)

    def add_link(self, fwID1, fwID2, ifnumm):
       self.StaticGraph.add_edge(fwID1, fwID2, interf=ifnumm)

    def forwarder_down(self, fwID):
       self.DynamicGraph.remove_edges_from(nx.edges(DynamicGraph, fwID))

    def forwarder_up(self, fwID):
       self.DynamicGraph.add_edges_from(StaticGraph.edges(fwID, data=True))

    def reload_topology(self):
       #DynamicGraph
       self.DynamicGraph = self.StaticGraph.to_directed()

    def get_tunnel(self, fwID1, fwID2, tunnelID, condition):
       hopy = nx.shortest_path(self.DynamicGraph, fwID1, fwID2)
       path = []
       #vystup = '\'' + tunnelID + '\'' + ', 0x0800, '
       for k in hopy[1:-1]:
          path.append(node(k,self.DynamicGraph[k][hopy[hopy.index(k)+1]]['interf']))
          #vystup = vystup + 'node(' + str(k) + ','
          #vystup = vystup + str(self.DynamicGraph[k][hopy[hopy.index(k)]]['interf']) + '), '
          #LOG.debug(vystup)
       t = tunnels(tunnelID, condition, path)
       return(t)


class StatsController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(StatsController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']
        self.topo = topology()
        self.id_pool = []

    def info(self, req, opt):
        resp = str(opt)
        LOG.debug('~~~~~~~~~~~~~~~~~~~~~~~~~debug~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
        return (Response(content_type='text', body=resp))

    def mod_pdp (self, req, cmd, mirror = 0):
        #vytiahneme parametre z tela REST spravy
        body = eval(req.body)
        #TID = str(body.get('TID'))
        start = int(body.get('start'))
        end = int(body.get('end'))
        condition = body.get('condition')
        two_way = body.get('mirror')
        #mirror_TID = body.get('mirror_TID')
        TID = self.get_mac()
        mirror_TID = self.get_mac()
        #vytvorime si instanciu triedy topology ktora ma graf siete
        #TODO: zvazit ci tuto instanciu radsej nevytvarat v __init__() triedy aby bola spolocna a nevytvarala sa nova pri kazdom volani mod_tunnel()
        topo = self.topo
        # do 't' dostaneme tunnel triedy 'tunnels' (na zaciatku)
        # v pripade ze mirror==1 (volanie mod_tunnel() pre vytvorenie tunela v opacnom smere) dostaneme spiatocny tunel 
        if mirror == 0:
            t = topo.get_tunnel(start, end, TID, condition)
        else:
            t = topo.get_tunnel(end, start, mirror_TID, condition)

        # premennej cmd priradime OFP konstantu na zaklade adresy REST volania /stats/tunnels/{cmd} 
        # zatial sa nepouziva, vzdy sa robi add
        dp = self.dpset.get(t.nodes[0].dpid)
        if cmd == 'add':
            self.cmd = dp.ofproto.OFPFC_ADD
        elif cmd == 'modify':
            self.cmd = dp.ofproto.OFPFC_MODIFY
        elif cmd == 'delete':
            self.cmd = dp.ofproto.OFPFC_DELETE
        else:
            return Response(status=404)

        ##########Tato cast je pre prvy node v tunely pretoze ten musi vykonat aj zmenu MAC adresy################
        parser = dp.ofproto_parser
        #momentalne je to trochu skarede lebo je to na tvrdo postavene na IP siet a dva druhy tunelov (jeden pre ARP druhy pre IP)
        if condition.get('ipv4_dst') == None:
            #TODO:predpokladame ze iniciator komunikacie je za portom 1, treba nejako elegantnejsie
            match = parser.OFPMatch(eth_type=condition.get('eth_type'), in_port=1)
        else:
            if mirror == 0:
                match = parser.OFPMatch(eth_type=condition.get('eth_type'), ipv4_dst=condition.get('ipv4_dst'))
            elif mirror == 1:
                match = parser.OFPMatch(eth_type=condition.get('eth_type'), ipv4_dst=condition.get('ipv4_src'))

        actions = [parser.OFPActionSetField(eth_src=t.TID), parser.OFPActionOutput(t.nodes[0].port_out)]
        self.add_flow(dp, 0, match, actions)
        ##########################################################################################################


        #########Tento cyklus prebehne vsetky ostatne nody kde sa pridaju len forwardovacie pravidla##############
        match = parser.OFPMatch(eth_src=t.TID)
        for var in t.nodes[1:]:
            dp = self.dpset.get(var.dpid)
            actions = [parser.OFPActionOutput(var.port_out)]
            self.add_flow(dp, 0, match, actions)
        ##########################################################################################################

        # Ak pride v RESTE 'mirror' : 'yes' na zaciatku sa to ulozi do premennej 'two_way'
        # kontrola na mirror == 0 zabezpecuje aby sa nerekurzovalo donekonecna lebo rekurzivne zavolana funkcia ma mirror == 1
        if two_way == 'yes' and mirror == 0:     
            LOG.debug('~~~~~~~~~~~~~~~~~~~~~~~~~~Debug~rekurs~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')  
            self.mod_pdp(req, cmd, 1)  
        return (Response(content_type='text', body='ok'))

    def add_flow(self, dp, priority, match, actions):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)

    
    def get_mac(self):
        mac_char='0123456789abcdef'
        mac_addr=''
        available=0
        while available == 0:
            for i in range(6):
                for y in range(2):
                    mac_addr = mac_addr + random.choice(mac_char)
                mac_addr = mac_addr + ':'

            mac_addr = mac_addr[:-1]
            if mac_addr not in self.id_pool:
                available = 1
        self.id_pool.append(mac_addr)
        return(mac_addr)


class RestStatsApi(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(RestStatsApi, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        mapper = wsgi.mapper

        wsgi.registory['StatsController'] = self.data
        path = '/gprs'

        uri = path + '/info/{opt}'
        mapper.connect('stats',uri,
                       controller=StatsController, action='info',
                       conditions=dict(method=['GET']))
  
        uri = path + '/pdp/{cmd}'
        mapper.connect('stats',uri,
                       controller=StatsController, action='mod_pdp',
		       conditions=dict(method=['POST']))

    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

