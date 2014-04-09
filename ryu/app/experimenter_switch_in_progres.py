from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3_parser
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_parser
from ryu.ofproto import inet
from ryu.app.wsgi import ControllerBase, WSGIApplication
from webob import Response
import struct
import sys
import logging
import networkx as nx
import json
import random
import socket

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
        self.add_link(0xa,0xb,3)
        self.add_link(0xb,0xa,1)
        
        #0xa <-> 0xd
        self.add_link(0xa,0xd,4)
        self.add_link(0xd,0xa,1)
    
        #0xb <-> 0xc
        self.add_link(0xb,0xc,3)
        self.add_link(0xc,0xb,1)

        #0xb <-> 0xd
        self.add_link(0xb,0xd,2)
        self.add_link(0xd,0xb,2)

        #0xc <-> 0xe
        self.add_link(0xc,0xe,2)
        self.add_link(0xe,0xc,2)

        #0xd <-> 0xe
        self.add_link(0xd,0xe,3)
        self.add_link(0xe,0xd,1)
      

        #end_linky
        #BSS node <-> 0xa
        self.add_link(0,0xa,1)
        self.add_link(0xa,0,1)
        #vGSN node <-> 0xa
        self.add_link(1,0xa,1)
        self.add_link(0xa,1,2)
        #internet <-> 0xc
        self.add_link(2,0xc,1)
        self.add_link(0xc,2,3)
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
       self.DynamicGraph = self.StaticGraph.to_directed()

    def get_tunnel(self, fwID1, fwID2, tunnelID, mirrorID):
       hopy = nx.shortest_path(self.DynamicGraph, fwID1, fwID2)
       path = []
       for k in hopy[0:-1]:
          path.append(node(k,self.DynamicGraph[k][hopy[hopy.index(k)+1]]['interf']))
       t = tunnels(tunnelID, mirrorID, path)
       return(t)
       
##################KONIEC: Uzly Tunely a topologia########################################


LOG = logging.getLogger('ryu.app.ofctl_rest')
BSS_PHY_PORT = 1
VGSN_PHY_PORT = 2

GPRS_SDN_EXPERIMENTER = int("0x42", 16)
OF_GPRS_TABLE = 2

#TODO: kazdy PDP kontext patri nejakej bss-ke
# mali by sme si spravit:
# 1) mechanizmus na pripojenie bss-ky. controller musi sniffovat komunikaciu 
#    medzi BSS a VGSN aby zistil, ze sa pripojila nova BSS. z komunikacie musi 
#    ziskat IP adresu BSS a VGSN a zdrojovy a cielovy port BSS a VGSN
#    XXX: casom sa mozu porty zmenit, ked restartujeme service na BSS
# 2) zoznam pripojenych bss-iek
# 3) v pdp-kontexte sa odkazovat na BSS-ku ku ktorej patri...
BSS_IP="1.2.3.4"
BSS_PORT=1234
VGSN_IP="14.13.12.11"
VGSN_PORT=23000
BSS_EDGE_FORWARDER=[0xa]
class PDPContext:
    def __init__(self, bvci, tlli, sapi, nsapi, tunnel_port, tunnel_internet, tunnel_bss, ip):
        self.bvci = bvci
        self.tlli = tlli
        self.sapi = sapi
        self.nsapi = nsapi
        #TODO: QoS a tunnel treba premysliet
        self.ip = ip
        self.tunnel_port = tunnel_port
        self.tunnel_internet = tunnel_internet
        self.tunnel_bss = tunnel_bss

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
#
#{'start' : '0x0', 'end' : '0x2', 'bvci' : '2', 'tlli' : '0xc5a4aeea', 'sapi' : '3', 'nsapi' : '5', 'mirror' : 'yes'}
#
# start = datapath ID of first forwarder in tunnel
# end = datapath ID of last forwarder in tunnel
# condition = dictionary of supported match rules
#     supperted match fields = eth_type, ipv4_src, ipv4_dst, eth_src, eth_dst
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

        uri = path + '/pdp/{cmd}'
        mapper.connect('stats',uri,
                       controller=RestCall, action='mod_pdp',
                       conditions=dict(method=['POST']))
        
#    def add_pdp_context(self, dp, pdp, tunnel):
#        """ Add new flow rule to redirect user traffic into tunnel interface.
#        
#        Keyword arguments:
#            dp -- datapath
#            pdp -- pdp context
#            tunnel -- outgoing interface number
#
#        """
#
#        print "add new OF rule to DP="+str(dp)
#
#        ofp = dp.ofproto
#        parser = dp.ofproto_parser
#
# pouzivatelsky packet s danymi parametrami tlacime do dodaneho tunelu
#        match = parser.OFPMatch(
#                        in_port=BSS_PHY_PORT,
#                        ns_type=0, 
#                        ns_bvci=pdp.bvci,
#                        bssgp_tlli=pdp.tlli,
#                        llc_sapi=pdp.sapi,
#                        sndcp_nsapi=pdp.nsapi)
#        actions = [ GPRSActionPopGPRSNS(), GPRSActionPopUDPIP() , parser.OFPActionOutput(port=tunnel) ]
#        inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
#        req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=10, match=match, instructions=inst);
#        dp.send_msg(req)
#
#		# v opacnom smere nam vypadavaju z tunelu nejake packety.. balime ich do gprsns a posielame na bss
#        # TODO: (mato) prepisat tento match, malo by sa matchovat:
#        #  - zdrojova a cielova mac adresa tunela
#        #  - cielova IP adresa (podla adresy ktoru ma priradeny PDP kontext)
#        match = parser.OFPMatch( 
#                in_port=TUNNEL_PHY_PORT,
#                eth_type=0x0800, 
#                eth_src=pdp.tunnel_internet,
#                eth_dst=pdp.tunnel_bss,
#                ipv4_dst=pdp.ip)
#       # TODO: (mato)
#       # adresa 10.11.12.13  adresa VGSN
#       # adresa 20.21.22.23 je adresa BSS 
#       # sp by mal byt port ktory sa nejako dozvieme (z prveho pripojenia BSS na VGSN)
#       # dp by mal byt port na ktorom pocuva BSS, tiez sa ho dozvieme z prveho pripojenia BSS
#      #XXX: kontrolny traffic z BSS na VGSN by sa mal asi posielat aj do controlleru, na analyzu cisiel portov?? minimalne na zaciatku
#        actions = [
#            GPRSActionPushGPRSNS( bvci=pdp.bvci, tlli=pdp.tlli, sapi=pdp.sapi, nsapi=pdp.nsapi),
#            GPRSActionPushUDPIP( sa=VGSN_IP, da=BSS_IP, sp=VGSN_PORT, dp=BSS_PORT),
#            parser.OFPActionOutput( port=BSS_PHY_PORT ) ] 
#        inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
#        req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=11, match=match, instructions=inst);
#        dp.send_msg(req)

    def on_inner_dp_join(self, dp):
        """ Add new inner (BSS side) forwarder joined our network.
        
        Keyword arguments:
            dp -- datapath

        """
        if dp.id in BSS_EDGE_FORWARDER:
            ofp = dp.ofproto
            parser = dp.ofproto_parser
            # zmazme vsetky existujuce pravidla
            dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE))
            dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE, table_id=OF_GPRS_TABLE))

            ##########################
            # hlavna flow tabulka (0)
    
            # UDP 23000 je GPRS-NS 
            inst = [ parser.OFPInstructionGotoTable(OF_GPRS_TABLE) ]
            match = parser.OFPMatch(eth_type=0x0800,ip_proto=inet.IPPROTO_UDP, udp_dst=VGSN_PORT)
            req = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
            dp.send_msg(req)
   
            #################
            # gprsns tabulka
            
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
    
            # konkretne user packety posunieme, kam ich treba
            #XXX: pravidla pridava funkcia add_pdp_context
            #TODO: pridat vsetky aktivne PDP kontexty
            #for pdp in self.active_contexts:
            #    self.add_pdp_context(dp, pdp, TUNNEL_PHY_PORT)
    
           # ak to ma sndcp, su to user data neznameho PDP kontextu - drop
            match = parser.OFPMatch( sndcp_first_segment=1 )
            actions = [ ]
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=1, match=match, instructions=inst)
            dp.send_msg(req)

           # vsetko ostatne je signalizacia - tlacime do vGSN
            actions = [ parser.OFPActionOutput(VGSN_PHY_PORT) ]
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=0, instructions=inst)
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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #TODO: check if this is new switch and add it to list of switches
        self.on_inner_dp_join(ev.msg.datapath)

    @set_ev_cls(ofp_event.EventOFPPortStatus)
    def vypadok(self, ev):
        print('~~~~~~~~~~~~~DEBUG~~~~~~~~~~~~~~~~~~~~~~~~~~')

class RestCall(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RestCall, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']
        self.topo = topology()
        self.id_pool = []

    def info(self, req, opt):
        resp = str(opt)
        LOG.debug('~~~DEBUG~~~')
        return (Response(content_type='text', body=resp))

    def mod_pdp (self, rest_body, cmd, mirror = 0, mirrorTID=0, TID=0):
        #vytiahneme parametre z tela REST spravy
        body = eval(rest_body.body)
        start = int(body.get('start'), 16)
        end = int(body.get('end'), 16)
        bvci = int(body.get('bvci'))
        tlli = int(body.get('tlli'), 16)
        sapi = int(body.get('sapi'))
        nsapi = int(body.get('nsapi'))
        #active_contexts.append( PDPContext(bvci, tlli, sapi, nsapi,'10.10.10.10', ) )
        two_way = body.get('mirror')
        if mirror == 0:
            mirrorTID = self.get_mac()
            TID = self.get_mac()
        #vytvorime si instanciu triedy topology ktora ma graf siete
        #TODO: zvazit ci tuto instanciu radsej nevytvarat v __init__() triedy aby bola spolocna a nevytvarala sa nova pri kazdom volani mod_tunnel()
        topo = self.topo
        # do 't' dostaneme tunnel triedy 'tunnels' (na zaciatku)
        # v pripade ze mirror==1 (volanie mod_tunnel() pre vytvorenie tunela v opacnom smere) dostaneme spiatocny tunel 
        t = topo.get_tunnel(start, end, TID, mirrorTID)
        
        # premennej cmd priradime OFP konstantu na zaklade adresy REST volania /stats/tunnels/{cmd} 
        # zatial sa nepouziva, vzdy sa robi add
        dp = self.dpset.get(t.nodes[1].dpid)
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
        ofp = dp.ofproto
   
        match = parser.OFPMatch( in_port=1,
                                 ns_type=0,
                                 ns_bvci=bvci, 
                                 bssgp_tlli=tlli, 
                                 llc_sapi=sapi, 
                                 sndcp_nsapi=nsapi)
                               
        actions = [GPRSActionPopGPRSNS(), GPRSActionPopUDPIP(),
                   parser.OFPActionSetField(eth_src=t.mirrorTID),parser.OFPActionSetField(eth_dst=t.TID),
                   parser.OFPActionOutput(t.nodes[1].port_out)]
        #inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
        #req = parser.OFPFlowMod(datapath=dp, match = match, table_id=OF_GPRS_TABLE, priority=10, instructions=inst)
        #dp.send_msg(req) 
        self.add_flow(dp, 10, match, actions, OF_GPRS_TABLE)

        ##########################################################################################################


        #########Tento cyklus prebehne vsetky ostatne nody kde sa pridaju len forwardovacie pravidla##############
        match = parser.OFPMatch(eth_dst=t.TID)
        for var in t.nodes[2:]:
            dp = self.dpset.get(var.dpid)
            actions = [parser.OFPActionOutput(var.port_out)]
            self.add_flow(dp, 10, match, actions, 0)
        ##########################################################################################################

        # Ak pride v RESTE 'mirror' : 'yes' na zaciatku sa to ulozi do premennej 'two_way'
        # kontrola na mirror == 0 zabezpecuje aby sa nerekurzovalo donekonecna lebo rekurzivne zavolana funkcia ma mirror == 1
        #if two_way == 'yes' and mirror == 0:     
        #    LOG.debug('~~~~~~~~~~~~~~~~~~~~~~~~~~Debug~rekurs~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')  
        #    self.mod_pdp(rest_body, cmd, 1, mirrorTID, TID)  
        return (Response(content_type='text', body='ok'))

    def add_flow(self, dp, priority, match, actions, table = 0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, table_id=table, match=match, instructions=inst)
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
