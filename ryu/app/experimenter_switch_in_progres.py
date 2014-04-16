from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3_parser
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller import handler
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
from ryu.ofproto import ofproto_parser
from ryu.ofproto import inet
from ryu.app.wsgi import ControllerBase, WSGIApplication
from webob import Response
from webob import Request
from cgi import parse_qs
import struct
import sys
import logging
import networkx as nx
import json
import random
import socket
import ast
import array
import inspect
import pprint

################Uzly, tunely a topologia#################

class node:
  def __init__(self, dpid, port_out):
    self.dpid = dpid
    self.port_out = port_out

class tunnels:
  def __init__(self, TID, mirrorTID,  nodes):
    self.TID = TID
    self.mirrorTID = mirrorTID
    self.nodes = nodes
    

class topology():

    def __init__(self):
        self.StaticGraph=nx.DiGraph()
        self.DynamicGraph=nx.DiGraph()
        #Vytovorenie topologie, staticke, kompatibilne s navrhom v dokumentacii
        #format:       Z uzlu
        #              |  Do Uzlu
        #              |   |   Linkou
        #              V   V   V
        #self.add_link(0xa,0xb,3)

        #0xa <-> 0xb
        #self.add_link(0xa,0xb,3)
        #self.add_link(0xb,0xa,1)
        
        #0xa <-> 0xd
        #self.add_link(0xa,0xd,4)
        #self.add_link(0xd,0xa,1)
    
        #0xb <-> 0xc
        #self.add_link(0xb,0xc,3)
        #self.add_link(0xc,0xb,1)

        #0xb <-> 0xd
        #self.add_link(0xb,0xd,2)
        #self.add_link(0xd,0xb,2)

        #0xc <-> 0xe
        #self.add_link(0xc,0xe,2)
        #self.add_link(0xe,0xc,2)

        #0xd <-> 0xe
        #self.add_link(0xd,0xe,3)
        #self.add_link(0xe,0xd,1)
      
        #TODO: odstranit staticke pseudo-nody
        #end_linky
        #BSS node <-> 0xa
        self.add_link('901-70-1-0',0xa,1)
        self.add_link(0xa,'901-70-1-0',1)
        #vGSN node <-> 0xa
        #XXX:self.add_link(1,0xa,1)
        #XXX:self.add_link(0xa,1,2)
        #internet <-> 0xc
        self.add_link('internet',0xc,1)
        self.add_link(0xc,'internet',3)
        self.reload_topology()

    def vymaz_tunel(tunelID):
        for hrana in ((u,v) for u,v,d in DynamicGraph.edges_iter(data=True) if tunelID in d['tunely']):
            self.DynamicGraph[hrana[0]][hrana[1]]['tunely'] = []

    def add_forwarder(self, fwID):
        self.StaticGraph.add_node(fwID)

    def add_link(self, fwID1, fwID2, ifnumm):
        self.StaticGraph.add_edge(fwID1, fwID2, interf=ifnumm, tunely=[])

    def link_down(fwID1, fwID2):
        for tunelID in DynamicGraph[fwID1][fwID2]['tunely']:
            vymaz_tunel(tunelID)
        self.DynamicGraph.remove_edge(fwID1, fwID2)

    def link_up(fwID1, fwID2):
        self.DynamicGraph.edge[fwID1][fwID2] = StaticGraph[fwID1][fwID2]
	
    def forwarder_down(self, fwID):
        tunelIDs = []
        for v in DynamicGraph[fwID].keys():
            tunelIDs += DynamicGraph[fwID][v]['tunely']
        for tunelID in tunelIDs:
            vymaz_tunel(tunelID)
        self.DynamicGraph.remove_edges_from(nx.edges(DynamicGraph, fwID))

    def forwarder_up(self, fwID):
        self.DynamicGraph.add_edges_from(StaticGraph.edges(fwID, data=True))

    def reload_topology(self):
        self.DynamicGraph = self.StaticGraph.to_directed()

    def get_tunnel(self, fwID1, fwID2, tunnelID, mirrorID):
        hopy = nx.shortest_path(self.DynamicGraph, fwID1, fwID2)
        path = []
        for k in hopy[1:-1]:
            path.append(node(k,self.DynamicGraph[k][hopy[hopy.index(k)+1]]['interf']))
            try:
                self.DynamicGraph[k][hopy[hopy.index(k)+1]]['tunely'] += [tunnelID]
            except NameError:
                self.DynamicGraph[k][hopy[hopy.index(k)+1]]['tunely'] = [tunnelID]
        t = tunnels(tunnelID, mirrorID, path)
        return(t)
       
##################KONIEC: Uzly Tunely a topologia########################################


LOG = logging.getLogger('ryu.app.ofctl_rest')
BSS_PHY_PORT = 1
VGSN_PHY_PORT = 2
INET_PHY_PORT = 3

GPRS_SDN_EXPERIMENTER = int("0x42", 16)
OF_GPRS_TABLE = 2

topo = topology()
#TODO: kazdy PDP kontext patri nejakej bss-ke
# mali by sme si spravit:
# 1) mechanizmus na pripojenie bss-ky. controller musi sniffovat komunikaciu 
#    medzi BSS a VGSN aby zistil, ze sa pripojila nova BSS. z komunikacie musi 
#    ziskat IP adresu BSS a VGSN a zdrojovy a cielovy port BSS a VGSN
#    XXX: casom sa mozu porty zmenit, ked restartujeme service na BSS
# 2) zoznam pripojenych bss-iek
# 3) v pdp-kontexte sa odkazovat na BSS-ku ku ktorej patri...
BSS_IP="192.168.27.125"
BSS_PORT=23000
VGSN_IP="192.168.27.2"
VGSN_PORT=23000
BSS_EDGE_FORWARDER=[0xa]
INET_EDGE_FORWARDER=[0xc]
class PDPContext:
    def __init__(self, bvci, tlli, sapi, nsapi, tunnel_out, tunnel_in, client_ip):
        self.bvci = bvci
        self.tlli = tlli
        self.sapi = sapi
        self.nsapi = nsapi
        #TODO: QoS a tunnel treba premysliet
        self.tunnels = []
        self.tunnels.append(tunnel_out)
        self.tunnels.append(tunnel_in)
        self.client_ip = client_ip
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
#{'start' : '0', 'end' : '2', 'bvci' : '2', 'tlli' : '0xc5a4aeea', 'sapi' : '3', 'nsapi' : '5', 'mirror' : 'yes'}
#
# start = datapath ID of first forwarder (or pseudo-node, BSS, vGSN etc.) in tunnel
# end = datapath ID of last forwarder (or pseudo-node like APN) in tunnel
# bvc, tlli, sapi, nsapi = parameters of PDP Context
# mirror = if 'yes' then tunnel will be created in backward dirrection too

active_contexts = []

class GPRSControll(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(GPRSControll, self).__init__(*args, **kwargs)

        # gprs_ns.pcap obsahuje jeden aktivny PDP kontext
        # TODO: o tom ake kontexty mame (a na ktorom datapathe) sa budeme 
        # dozvedat dynamicky cez REST
        # zatial, kazdy datapath ma vsetky kontexty
        #self.active_contexts.append( PDPContext(bvci=2, tlli=0xc5a4aeea, sapi=3, nsapi=5, tunnel_port=TUNNEL_PHY_PORT, tunnel_internet='00:00:00:00:00:01', tunnel_bss='00:00:00:00:00:02', ip='10.10.10.10') )
        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        mapper = wsgi.mapper

        wsgi.registory['RestCall'] = self.data
        path = '/gprs'
         
        uri = path + '/info/{opt}'
        mapper.connect('stats',uri,
                       controller=RestCall, action='info',
                       conditions=dict(method=['GET']))

        #volanie na uri /gprs/pdp/{add/mod/del} spusti funkciu mod_pdp v triede RestCall
        uri = path + '/pdp/{cmd}'
        mapper.connect('stats',uri,
                       controller=RestCall, action='parse_GET',
                       conditions=dict(method=['GET']))
        
        uri = path + '/pdp/{cmd}'
        mapper.connect('stats',uri,
                       controller=RestCall, action='mod_pdp',
                       conditions=dict(method=['POST']))
        
    def on_inner_dp_join(self, dp):
        """ Add new inner (BSS side) forwarder joined our network.
        
        Keyword arguments:
            dp -- datapath

        TODO:
          VGSN inside our SDN network -- routing of GPRS-NS traffic

        """
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        # zmazme vsetky existujuce pravidla
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE))
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE, table_id=OF_GPRS_TABLE))

        ##########################
        # hlavna flow tabulka (0)
        #Discovery ping (test ipv4_dst=0.0.0.2) ide na controller
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst='0.0.0.2')
        actions = [ parser.OFPActionOutput(ofp.OFPP_CONTROLLER) ]
        self.add_flow(dp, 100, match, actions) 

        if dp.id in INET_EDGE_FORWARDER:
            # send all ARP requests to forwarder
            match = parser.OFPMatch(in_port=INET_PHY_PORT, eth_type=0x0806, arp_op=1)
            actions = [ parser.OFPActionOutput(ofp.OFPP_CONTROLLER) ]
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            req = parser.OFPFlowMod(datapath=dp, priority=10, match=match, instructions=inst)
            dp.send_msg(req)

        if dp.id in BSS_EDGE_FORWARDER:

            # UDP 23000 je GPRS-NS 
            inst = [ parser.OFPInstructionGotoTable(OF_GPRS_TABLE) ]
            match = parser.OFPMatch(eth_type=0x0800,ip_proto=inet.IPPROTO_UDP, udp_dst=VGSN_PORT)
            req = parser.OFPFlowMod(datapath=dp, priority=200, match=match, instructions=inst)
            dp.send_msg(req)

            # VGSN_PHY a BSS_PHY porty su prebridgeovane -- DHCP, ARP, Abis & stuff
            # XXX: co ak bss a vgsn nie su spolu na jednom DPID?
            actions = [ parser.OFPActionOutput(VGSN_PHY_PORT) ]
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            match = parser.OFPMatch(in_port=BSS_PHY_PORT)
            req = parser.OFPFlowMod(datapath=dp, priority=10, match=match, instructions=inst)
            dp.send_msg(req)
            actions = [ parser.OFPActionOutput(BSS_PHY_PORT) ]
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            match = parser.OFPMatch(in_port=VGSN_PHY_PORT)
            req = parser.OFPFlowMod(datapath=dp, priority=10, match=match, instructions=inst)
            dp.send_msg(req)

   
            #################
            # gprsns tabulka
            #TODO:Pre forwardovacie pravidla tabulka #3
            #TODO:handlovanie BSS_phy_port <-> VGSN_PHY_PORT
            #TODO: zrusenie PDP contextu
            #TODO: pridelovanie adries z controlleru
            #TODO: arp mac adresu internetu
            #TODO: upratat icmp,arp a sracky okolo generovani paketov
            # ak je to nie je prvy SNDCP fragment pouzivatelskeho packetu, DROP
            match = parser.OFPMatch( sndcp_first_segment=0 )
            actions = [ ] 
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=20, match=match, instructions=inst)
            dp.send_msg(req)
            
            # ak je to prvy SNDCP fragment packetu s viac ako jednym fragmentom, ICMP a DROP
            match = parser.OFPMatch( sndcp_first_segment=1, sndcp_more_segments=1 )
            actions = [ ] #TODO: ICMP a drop
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=20, match=match, instructions=inst)
            dp.send_msg(req)
    
           # ak to ma sndcp, su to user data neznameho PDP kontextu - drop
            match = parser.OFPMatch( sndcp_first_segment=1 )
            actions = [ ]
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=1, match=match, instructions=inst)
            dp.send_msg(req)

           # vsetko ostatne je signalizacia - tlacime do vGSN, alebo BSS
            # XXX: co ak bss a vgsn nie su spolu na jednom DPID?
            actions = [ parser.OFPActionOutput(VGSN_PHY_PORT) ]
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            match = parser.OFPMatch(in_port=BSS_PHY_PORT)
            req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=0, match=match, instructions=inst)
            dp.send_msg(req)
            actions = [ parser.OFPActionOutput(BSS_PHY_PORT) ]
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            match = parser.OFPMatch(in_port=VGSN_PHY_PORT)
            req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=0, match=match, instructions=inst)
            dp.send_msg(req)

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

    #@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    #def switch_features_handler(self, ev):
    #    #TODO: check if this is new switch and add it to list of switches
    #    self.on_inner_dp_join(ev.msg.datapath)
 
    #@set_ev_cls(ofp_event.EventOFPPortStatus)
    #def vypadok(self, ev):
    #    print('~~~~~~~~~~~~~DEBUG~~~~~~~~~~~~~~~~~~~~~~~~~~')
 
    def _ping(self, dp, port_out):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0800,
                                           dst='ff:ff:ff:ff:ff:ff',
                                           src='aa:aa:aa:aa:aa:aa'))

        pkt.add_protocol(ipv4.ipv4(dst='0.0.0.2',
                                   src='0.0.0.1',
                                   proto=1))

        pkt.add_protocol(icmp.icmp(type_=8,
                                   code=0,
                                   csum=0,
                                   data=icmp.echo(1,1,"{'dpid' : "+str(dp.id)+",'port_out' : "+str(port_out)+"}")))
        pkt.serialize()
        data=pkt.data
        actions=[parser.OFPActionOutput(port_out,0)]
        out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=data)
        dp.send_msg(out)
    
    #@set_ev_cls(ofp_event.EventOFPPortStatus)
    #def port_change(self, ev):
        #print(inspect.getmembers(ev.msg))
        #print(ev.msg.datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn)
    def _packet_in(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = ev.msg.match

        if match['eth_type'] == 0x0806 and match['arp_op'] == 1:
            LOG.debug("prisiel nam ARP request... ")
            for context in active_contexts:
                if match['arp_tpa'] == context.client_ip:
                    reply_mac = context.tunnels[0].TID
            eth = ethernet.ethernet(match['arp_sha'], dp.id, ether.ETH_TYPE_ARP)
            arp_reply = arp.arp_ip(2, reply_mac, match['arp_tpa'], match['arp_sha'], match['arp_spa'])
            LOG.debug("  arp_reply="+pprint.pformat(arp_reply))

            pkt = packet.Packet()
            pkt.add_protocol(eth)
            pkt.add_protocol(arp_reply)
            pkt.serialize()
            actions=[parser.OFPActionOutput(match['in_port'])]
            out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=pkt.data)
            dp.send_msg(out)

        if match['eth_type'] == 0x0800 and match['ipv4_dst'] == '0.0.0.2' and match['ip_proto'] == 1:
            neighbourDPID=self._get_icmp_data(packet.Packet(array.array('B', ev.msg.data)),'dpid')
            neighbourPort=self._get_icmp_data(packet.Packet(array.array('B', ev.msg.data)),'port_out')
            #print('Som',ev.msg.datapath.id,
            #      ', dostal som spravu na porte: ',ev.msg.match['in_port'], 
            #      ' od cisla:',nieghbourDPID,
            #      ' ktory ma ma pripojeneho na porte',neighbourPort)
            topo.add_link(ev.msg.datapath.id, neighbourDPID, ev.msg.match['in_port'])
            topo.add_link(neighbourDPID, ev.msg.datapath.id, neighbourPort )
            topo.reload_topology()
            LOG.debug('Topology changed')

    @set_ev_cls(ofp_event.EventOFPStateChange)
    def switch_woke_up(self, ev):
        if ev.state == handler.MAIN_DISPATCHER:
            self.on_inner_dp_join(ev.datapath)
            dp = ev.datapath
            ofp = dp.ofproto
            parser = dp.ofproto_parser
            for var in dp.ports:
                if var != (ofp.OFPP_CONTROLLER+1):
                    self._ping(dp,var)
        if ev.state == handler.DEAD_DISPATCHER:
            for context in active_contexts:
                print('mam PDP context')
                for tunnels in context.tunnels:
                    for nodes in tunnels:
                        print('node: ',node.dpid)
            print('##################################################################')

    def _get_icmp_data(self, pkt, req):

        payload = ''
        for p in pkt:
            if p.protocol_name == 'icmp':
                for char in p.data.data:
                    payload+=(chr(char))
        slovnik = ast.literal_eval(payload.rstrip('\0'))
        return(slovnik.get(req))


    def add_flow(self, dp, priority, match, actions):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)


class RestCall(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RestCall, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']
        self.id_pool = []

    def parse_GET(self, req, cmd):
        #print(req.query)
        resp = str(cmd)
        args=[]
        result={}
        GET_data=''
        for var in cmd:
            if var == '&':
                args.append(GET_data)
                GET_data=''
                continue
            GET_data+=var
        args.append(GET_data)
        cnt=False
        
        for var in args:
            cnt=False
            key=''
            value=''
            for char in var:
                if char == '=':
                    cnt=True
                    continue
                if cnt == False:
                    key+=char
                if cnt == True:
                    value+=char
            if value != '':
                result[str(key)] = str(value)
        req.body=bytes(result)
        self.mod_pdp(rest_body=req, cmd='add')
        return (Response(content_type='text', body='{"address":"172.20.85.145","dns1":"8.8.8.8","dns2":"8.8.4.4"}'))

    def mod_pdp (self, rest_body, cmd, mirror = 0, TID=0, mirrorTID=0, t_out=None, t_in=None):
        #vytiahneme parametre z tela REST spravy
        body = ast.literal_eval(rest_body.body)
        pprint.pformat(self)
        LOG.debug('vytvaram tunel s parametrani: ')
        LOG.debug('self='+pprint.pformat(self))
        LOG.debug('body='+pprint.pformat(body))
        start = str(body.get('rai'))
        end = str(body.get('apn'))
        bvci = int(body.get('bvci'))
        tlli = int(body.get('tlli'), 16)
        sapi = int(body.get('sapi'))
        nsapi = int(body.get('nsapi'))
        client_ip = '172.20.85.145'
        two_way = 'yes'
        if mirror == 0:
            mirrorTID = self.get_mac()
            TID = self.get_mac()
            t_out = topo.get_tunnel(start, end, TID, mirrorTID)
            t_in = topo.get_tunnel(end, start, mirrorTID, TID)

        # do 't' dostaneme tunnel triedy 'tunnels'
        #pri tunely semrom von start -> end
        #pri tunely smerom dnu end -> start
        
        #TODO: Handlovanie 'cmd' hodnoty
        active_contexts.append( PDPContext(bvci, tlli, sapi, nsapi, t_out, t_in, client_ip, ) )
        print(t_out.nodes)
        ############################################Smerom von##############################################################################
        if mirror==0:
            ######Tato cast je pre prvy node v tunely smerom von, pretoze ten musi decapsulovat GPRS-NS aj zmenit MAC adresy################
            dp = self.dpset.get(t_out.nodes[0].dpid)
            parser = dp.ofproto_parser
            match = parser.OFPMatch( in_port=1,
                                     ns_type=0,
                                     ns_bvci=bvci, 
                                     bssgp_tlli=tlli, 
                                     llc_sapi=sapi, 
                                     sndcp_nsapi=nsapi)
                               
            actions = [GPRSActionPopGPRSNS(), GPRSActionPopUDPIP(),
                       parser.OFPActionSetField(eth_src=t_out.mirrorTID),parser.OFPActionSetField(eth_dst=t_out.TID),
                       parser.OFPActionOutput(t_out.nodes[0].port_out)]
            self.add_flow(dp, 10, match, actions, OF_GPRS_TABLE)

            ###############################################################################################################################

            #########Tento cyklus prebehne pre vsetky ostatne nody kde sa pridaju len forwardovacie pravidla a na poslednom sa setne broadcast eth_dst#
            for var in t_out.nodes[1:]:
                dp = self.dpset.get(var.dpid)
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_dst=t_out.TID)
                actions = [parser.OFPActionOutput(var.port_out)]
                # XXX: upratat podla topologie
                if var.dpid == 0xc:
                    #XXX: MAC adresu sa ucime cez ARP na poziadavku...
                    actions.insert(0,parser.OFPActionSetField(eth_dst='8e:bd:5a:41:f2:d4'))
                if var.dpid == 0xa:
                    actions.insert(0,parser.OFPActionSetField(eth_dst='ff:ff:ff:ff:ff:ff'))
                self.add_flow(dp, 10, match, actions, 0)
            ###############################################################################################################################
        
        ###################################Smerom dnu######################################################################################
        if mirror==1:
            dp = self.dpset.get(t_in.nodes[0].dpid)
            parser = dp.ofproto_parser
            ######################################Prvy paket na zaklade cielovej IP adresy (client_ip) natlacit do tunelu###################
            LOG.debug('  tin='+pprint.pformat(t_in))
            LOG.debug('  tout='+pprint.pformat(t_out))
            LOG.debug('  port_out='+pprint.pformat(t_in.nodes[0].port_out))
            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=client_ip) 
            actions = [parser.OFPActionSetField(eth_src=mirrorTID), parser.OFPActionSetField(eth_dst=TID),
                       parser.OFPActionOutput(t_in.nodes[0].port_out)]
            self.add_flow(dp, 11, match, actions, 0)
            
            #########Tento cyklus prebehne pre vsetky ostatne nody kde sa pridaju len forwardovacie pravidla a na poslednom sa pushnu GPRS signalizacne veci#
            for var in t_in.nodes[1:]:
                dp = self.dpset.get(var.dpid)
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_dst=t_in.TID)
                actions = [parser.OFPActionOutput(var.port_out)]
                if var.dpid == 0xa:
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=client_ip)
                    actions.insert(0, parser.OFPActionSetField(eth_dst='00:d0:cc:08:02:ba'))
                    actions.insert(0, GPRSActionPushUDPIP(sa=VGSN_IP, da=BSS_IP, sp=VGSN_PORT, dp=BSS_PORT))
                    actions.insert(0, GPRSActionPushGPRSNS(bvci, tlli, sapi, nsapi)) 
                self.add_flow(dp, 11, match, actions, 0)
            ###############################################################################################################################
            
        
        # Ak pride v RESTE 'mirror' : 'yes' na zaciatku sa to ulozi do premennej 'two_way'
        # kontrola na mirror == 0 zabezpecuje aby sa nerekurzovalo donekonecna lebo rekurzivne zavolana funkcia ma mirror == 1
        if two_way == 'yes' and mirror == 0:     
            self.mod_pdp(rest_body, cmd, 1, mirrorTID, TID, t_out, t_in)
        return (Response(content_type='text', body='{"address":"'+client_ip+'","dns1":"8.8.8.8","dns2":"8.8.4.4"}'))

    def add_flow(self, dp, priority, match, actions, table = 0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, table_id=table, match=match, instructions=inst)
        dp.send_msg(mod)

    #generator mac adresy pre ID tunela    
    def get_mac(self):
        mac_char='0123456789abcdef'
        mac_addr='02:'
        available=0
        while available == 0:
            for i in range(5):
                for y in range(2):
                    mac_addr = mac_addr + random.choice(mac_char)
                mac_addr = mac_addr + ':'

            mac_addr = mac_addr[:-1]
            if mac_addr not in self.id_pool:
                available = 1
        self.id_pool.append(mac_addr)
        print(mac_addr)
        return(mac_addr)

class GPRSAction(ofproto_v1_3_parser.OFPActionExperimenter):
    subtype = 0

    def __init__(self, subtype):
        super(GPRSAction, self).__init__(experimenter=GPRS_SDN_EXPERIMENTER)
        self.subtype = subtype
        self.len = 16

    def serialize(self, buf, offset):
        """ Serialize action into buffer. """
        super(GPRSAction,self).serialize(buf, offset)
        ofproto_parser.msg_pack_into("!H", buf, offset+8, self.subtype)

class GPRSActionPushGPRSNS(GPRSAction):
    def __init__(self, bvci, tlli, sapi, nsapi):
        super(GPRSActionPushGPRSNS,self).__init__(0x0001)
        self.len = 24
        self.bvci = bvci
        self.tlli = tlli
        self.sapi = sapi
        self.nsapi = nsapi

    def serialize(self, buf, offset):
        """ Serialize PushGPRSNS action into buffer. """
        super(GPRSActionPushGPRSNS,self).serialize(buf, offset)
        ofproto_parser.msg_pack_into("!HxxIHBBxxxx", buf, offset+8, 
                self.subtype, self.tlli, self.bvci, self.sapi, self.nsapi)

class GPRSActionPopGPRSNS(GPRSAction):
    def __init__(self):
        super(GPRSActionPopGPRSNS,self).__init__(0x0002)

class GPRSActionPushUDPIP(GPRSAction):
    def __init__(self, dp, sp, da, sa):
        super(GPRSActionPushUDPIP,self).__init__(0x0003)
        self.len = 24
        self.sp = sp
        self.dp = dp
        self.da = socket.inet_aton(da)
        self.sa = socket.inet_aton(sa)

    def serialize(self, buf, offset):
        """ Serialize PushUDPIP action into buffer. """
        super(GPRSActionPushUDPIP,self).serialize(buf, offset)
        ofproto_parser.msg_pack_into("!Hxx4s4sHH", buf, offset+8, 
                self.subtype, self.da, self.sa, self.dp, self.sp)

class GPRSActionPopUDPIP(GPRSAction):
    def __init__(self):
        super(GPRSActionPopUDPIP,self).__init__(0x0004)
