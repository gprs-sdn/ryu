from __future__ import division
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3_parser
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller import handler
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
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
#from networkx.readwrite import json_graph
import struct
import sys
import logging
import networkx as nx
from networkx.readwrite import json_graph
import json
import random
import socket
import ast
import array
import inspect
import pprint
import time
import urlparse
import datetime
import threading

from operator import attrgetter





################################################################
#                                                              #
#                                                              #
#                                                              #
# EXPERIMENTAL VERSION OF CONTROLLER WITH TRAFFIC ENGINEERING  #
#                                                              #
#                                                              #
################################################################






###Global variable initialization

##logger
##Usage: LOG.debug() / LOG.warning() / LOG.error()
LOG = logging.getLogger('ryu.app.experimenter_switch_in_progres.py')

##Static definition of of ports for vGSN and BSS
##TODO: Remove static definition(Either self-discovery or Yang)
BSS_PHY_PORT = 1
VGSN_PHY_PORT = 2
INET_PHY_PORT = None

##IP adresses used when controller generates packets
DISCOVERY_IP_SRC='10.1.1.252'
DISCOVERY_IP_DST='10.1.1.253'
##Due to nature of ARP protocol, DISCOVERY_ARP_IP must be in same subnet as host you want to discover
DISCOVERY_ARP_IP='172.20.255.99'
SNDCP_FRAG_WARNING_SRC_IP='224.42.42.3'

##Experimenter ID (self-assigned)
GPRS_SDN_EXPERIMENTER = int("0x42", 16)

##Number of OF table that contains GPRS-related flow rules on the way OUT
OF_GPRS_TABLE = 2
## access rules should be unified in one table--> ACCESS TABLE
ACCESS_TABLE_OUT = 2

##Number of OF table that contains GPRS-related flow rules on th way IN
OF_GPRS_TABLE_IN = 4
ACCESS_TABLE_IN = 4

##Number of OF table that contains MAC_TUNNEL-related flow rules
MAC_TUNNEL_TABLE = 3


#
##
### New Flow table constants
##
#

INGRESS_TABLE=0                  #first ingress table
ACESSS_ADAPTATION_TABLE_IN_1=1   #decapsulation from special headers (e.g. GPRS)
ACCESS_ADAPTATION_TABLE_IN_2=2   #decapsulation from special headers (e.g. GPRS)
MAC_TUNNEL_TABLE=3               #MAC tunnel switching
ACCESS_ADAPTATION_TABLE_OUT=4    #encapsulation to special headers (e.g. GPRS), NAT, forwarder output

##Hardcode IP adresses of our GPRS nodes
BSS_IP="192.168.27.125"
BSS_PORT=23000
VGSN_IP="192.168.27.2"
VGSN_PORT=23000

##Forwarders assigned to special groups
##XXX:Review usefulness


#
##
## WMNC we are not going to use GPRS extensions, just MAC forwarding in this iPerf setup
##
#
#BSS_EDGE_FORWARDER=[0xa]
BSS_EDGE_FORWARDER=[]


#INET_EDGE_FORWARDER=[0xc]
INET_EDGE_FORWARDER=[]

LAN_TYPE_FORWARDERS=[0xa, 0xc]
BSS_TYPE_FORWARDERS=[]
INET_TYPE_FORWARDERS=[]



##Generation of IP adresses  asigned to devices on PDP CNT actiavation
##XXX:Modify pool if needed
IP_POOL=[]
for i in range(100,199):
    IP_POOL.append('172.20.85.'+str(i))


##List of APNs in network
APN_POOL=[]

##List of BSSs in network
#XXX:for now it's static
BSS_POOL=['901-70-1-0']
#BSS_POOL=['231-1-1-0']

##List of active PDP CNTs
ACTIVE_CONTEXTS = []

##List of tunnels
TUNNELS=[]


##List of used Tunnel identifiers
TID_POOL = []

## Temporary solution till I will have time to implement a decent routing table
routesList = []

## For measurement purposes
MEASUREMENT_CHECK = 5
MEASUREMENT_INTERVAL = 0
MEASUREMENT_TIMEOUT = 1
NON_MEASURED_LINK = -1

CLASS_ONE = [34, 36, 38, 46]
CLASS_TWO = [16, 18, 20, 22, 24, 26, 28, 30, 32, 40, 48]

CLASS_ONE_LAT = 0.10
CLASS_ONE_LAT_VAR = 0.02
CLASS_TWO_LAT = 1

odd_meters = [1,3,5,7,9]
even_meters = [2,4,6,8,10]

###Topology and topology-related classes

class link:
    """Link between two nodes in network, has only one direction
       and is defined by forwarder(dpid) and its egress port(port_out)

       Keyword arguments:
           dpid -- datapath ID
           port_out -- Egress port
    """
    def __init__(self, dpid, port_out):
        self.dpid = dpid
        self.port_out = port_out


class tunnel:
    """
    Tunnel contains endpoints (BSS/APN), path between these nodes in both directions(IN/OUT)
    and identifiers for these paths

    Keyword arguments:

        _bss_ -- BSS endpoint idetifier in topology (can be string)
        _apn_ -- APN endpoint (must be of apn class)
        tid_out -- Tunnel identifier in outgoing direction (MAC addr. format)
        tid_in -- Tunnel identifier in incoming dirrection (MAC addr. format)
        path_out -- list of links for outgoing direction
        path_in -- list of links for incoming direction
    """
    def __init__(self,_bss_, _apn_, _tid_out, _tid_in, path_out=None, path_in=None):
        self.bss = _bss_
        self.apn = _apn_
        self.tid_out = _tid_out
        self.tid_in = _tid_in
        self.path_in = path_in
        self.path_out = path_out



class plainMacTunnel:
    """
    WMNC hack
    Tunnel contains endpoints (APN/APN), path between these nodes in both directions(IN/OUT)
    and identifiers for these paths

    Keyword arguments:

        _sApn_ -- BSS endpoint idetifier in topology (can be string)
        _dApn_ -- APN endpoint (must be of apn class)
        tid_out -- Tunnel identifier in outgoing direction (MAC addr. format)
        tid_in -- Tunnel identifier in incoming dirrection (MAC addr. format)
        path_out -- list of links for outgoing direction
        path_in -- list of links for incoming direction
        path_out_str -- list of nodes for outgoing direction
        path_in_str -- list of nodes for incoming direction
    """
    def __init__(self,_sApn_, _dApn_, _tid_out, _tid_in, path_out=None, path_in=None, path_out_str=None, path_in_str=None, po_edges=None, pi_edges=None,max_util=NON_MEASURED_LINK, meter_id=NON_MEASURED_LINK,
                 path_out_lat=NON_MEASURED_LINK, path_out_latVar=NON_MEASURED_LINK, path_in_lat=NON_MEASURED_LINK, path_in_latVar=NON_MEASURED_LINK,):
        self.sApn = _sApn_
        self.dApn = _dApn_
        self.tid_out = _tid_out
        self.tid_in = _tid_in
        self.path_out = path_out
        self.path_in = path_in

        self.path_out_str = path_out_str
        self.path_in_str = path_in_str

        self.po_edges = po_edges
        self.pi_edges = pi_edges

        self.path_out_lat = path_out_lat
        self.path_out_latVar = path_out_latVar
        self.path_in_lat = path_in_lat
        self.path_in_latVar = path_in_latVar

        self.upl=None
        self.util_out=None
        self.util_in=None
        self.max_util_out = max_util
        self.max_util_in = max_util
        self.util_out_perc = 0
        self.util_in_perc = 0

        self.loss = False

        self.meter_id = meter_id


class apn:
    """
    Acces point defined by its name, IP and mac addr. APN's only mandatory arg. is name
    IP and mac addr. are resolved with DNS/ARP provided there is DNS entry available

    Keyword arguments:
        name -- Acces Point Name (string)
        ip_addr -- IP address of APN
        arp_origin_ip -- IP address to be used as source addres during APN discovery
        origin_eth_addr -- port MAC of physical interface (used for testing with virtual to host communication)
        eth_addr -- MAC address of APN
        dp -- forwarder on which is APN residing (due to filtering of APN request)
        port -- port of given forwarder where is APN residing (due to filtering of APN requests)
    """
    def __init__(self, name, ip_addr=None, arp_origin_ip=None, eth_addr=None, origin_eth_addr=None,  dpid=None, port=None):
        self.name = name
        self.ip_addr = ip_addr
        self.arp_origin_ip = arp_origin_ip
        self.eth_addr = eth_addr
        self.origin_eth_addr = origin_eth_addr
        self.dpid = dpid
        self.port = port


##XXX:maybe should be created from config file (Yang?)
# APN_POOL.append(apn('internet'))
# added for test
APN_POOL.append(apn('iperfclient', ip_addr=None, arp_origin_ip="192.168.90.101", eth_addr=None, dpid=10, port=1))
APN_POOL.append(apn('iperfserver', ip_addr=None, arp_origin_ip="192.168.92.101", eth_addr=None, dpid=12, port=3))

TunnelAdded = False


class topology():
    """
    Topology class maintains graph of links between all nodes in network
    """
    def __init__(self):
        self.StaticGraph=nx.DiGraph()
        self.DynamicGraph=nx.DiGraph()
        ##Static adding of nodes into topology (run reload_topology() after last modification)
        ##format:       From node
        ##              |  To node
        ##              |   |   Via port
        ##              V   V   V
        ##self.add_link(0xa,0xb,3)

        ##Below is static initialization of our test topology
        ##Uncomment in case of self-discovery fail
        ##0xa <-> 0xb
        #self.add_link(0xa,0xb,3)
        #self.add_link(0xb,0xa,1)

        ##0xa <-> 0xd
        #self.add_link(0xa,0xd,4)
        #self.add_link(0xd,0xa,1)

        ##0xb <-> 0xc
        #self.add_link(0xb,0xc,3)
        #self.add_link(0xc,0xb,1)

        ##0xb <-> 0xd
        #self.add_link(0xb,0xd,2)
        #self.add_link(0xd,0xb,2)

        ##0xc <-> 0xe
        #self.add_link(0xc,0xe,2)
        #self.add_link(0xe,0xc,2)

        ##0xd <-> 0xe
        #self.add_link(0xd,0xe,3)
        #self.add_link(0xe,0xd,1)

        ##TODO: Remove static nodes (BSS/vGSN remaining)

        ##Links between edge forwarders and non-SDN nodes
        ##BSS node <-> 0xa

# WMNC: lets not focus on BTS forwarder
#        self.add_link('901-70-1-0',0xa,1)
#       self.add_link(0xa,'901-70-1-0',1)


        #vGSN node <-> 0xa
        #XXX:self.add_link(1,0xa,1)
        #XXX:self.add_link(0xa,1,2)
        #internet <-> 0xc
        #self.add_link('internet',0xc,1)
        #self.add_link(0xc,'internet',3)

        #adding iPerf client and server manually
        #self.add_link('iperfclient', 0xa, 1, NON_MEASURED_LINK, NON_MEASURED_LINK)
        #self.add_link(0xa, 'iperfclient', 1, NON_MEASURED_LINK, NON_MEASURED_LINK)
        #self.add_link('iperfserver', 0xc, 1, NON_MEASURED_LINK, NON_MEASURED_LINK)
        #self.add_link(0xc, 'iperfserver', 3, NON_MEASURED_LINK, NON_MEASURED_LINK)
        self.reload_topology()

    def dump(self):
	data = json_graph.node_link_data(self.DynamicGraph)
	return json.dumps(data)

    def add_forwarder(self, fwID):
        self.StaticGraph.add_node(fwID)

    def del_forwarder(self, fwID):
        self.DynamicGraph.remove_node(fwID)

    #Latency = -1 for APN link
    def add_link(self, fwID1, fwID2, ifnum, linkLatency=NON_MEASURED_LINK, lastLatUpdate=NON_MEASURED_LINK, lossFlag = False, lossDuration = 0,
                 tx_bytes = NON_MEASURED_LINK, utilization = NON_MEASURED_LINK, delayVariation = NON_MEASURED_LINK, upl=0):
        self.StaticGraph.add_edge(fwID1, fwID2, interf = ifnum, lat = linkLatency, upt = lastLatUpdate, loF = lossFlag, loD = lossDuration, tx_b = tx_bytes,
                                  util = utilization, pdv = delayVariation, upl=upl)

    def link_down(fwID1, fwID2):
        self.DynamicGraph.remove_edge(fwID1, fwID2)

    def link_up(fwID1, fwID2):
        self.DynamicGraph.edge[fwID1][fwID2] = StaticGraph[fwID1][fwID2]

    def forwarder_down(self, fwID):
        self.DynamicGraph.remove_edges_from(nx.edges(DynamicGraph, fwID))

    def forwarder_up(self, fwID):
        self.DynamicGraph.add_edges_from(StaticGraph.edges(fwID, data=True))

    def reload_topology(self):
        self.DynamicGraph = self.StaticGraph.to_directed()

    #get_tunnel
    def build_path(self, hops):
        path = []
        for k in hops[1:-1]:
            #LOG.debug('PATH BUILD: Hop: ' + str(k) + ' HopIndex+1(nexthop): ' + str(hops[hops.index(k)+1]) + ' interface: ' + str(self.DynamicGraph[k][hops[hops.index(k)+1]]['interf']))
            path.append(link(k,self.DynamicGraph[k][hops[hops.index(k)+1]]['interf']))
        return path


##Topology initialization
topo = topology()



## convert IMSI string into byte array
def imsi_to_bytes(imsi_string):
  imsi_digits = list(imsi_string)
  imsi_bytes = [0,0,0,0,0,0,0,0]
  digit_no = 0

  # imsi is too long... fetch only first 15 characters and nag..
  if len(imsi_digits) > 15:
    print "imsi too long... "
    imsi_digits = imsi_digits[:15]

  # lower 3 bits indicate IMSI number... (0x1)
  imsi_bytes[0] = 0x1

  # convert string to bytes...
  for digit in imsi_digits:
    byte_no = (digit_no+1) / 2;
    if digit_no % 2:
      imsi_bytes[byte_no] |= int(digit, 16)
    else:
      imsi_bytes[byte_no] |= int(digit, 16) << 4
    digit_no += 1

  # if we have odd number of digits, set 4th bit to 1
  # and fill last octets upper nibble with 0xf
  if not len(imsi_digits)%2:
    imsi_bytes[0] |= 0x8
    imsi_bytes[(digit_no+1)/2] |= 0xf0

  return imsi_bytes

def _arp_send(dp, port_out, arp_code,  ip_sender, ip_target, eth_dst='ff:ff:ff:ff:ff:ff',eth_src=None,eth_target='00:00:00:00:00:00'):
    """
    Generates arp request and sends it out of 'port_out' of 'dp' forwarder

    Keyword arguments:
        dp -- Datapath
        port_out -- Port on forwarder (dp) used to spit out packet
        arp_code -- ARP OP code(1==reques, 2==reply)
        ip_sender -- Senders IP addres
        eth_dst  -- Ethernet destination address (in case of request, broadcast address is used)
        eth_src -- Ethernet source address. If none provided, it's generated from Datapath ID of sending forwarder (dp)
        eth_target -- Final recipients Ethernet address(in case of request, zeroed out address is used)
        ip_target --  Final recipients IP address
    """

    ofp = dp.ofproto
    parser = dp.ofproto_parser
    pkt = packet.Packet()

    # HACK: to reply as real interface on virtual machine
    if dp.id in LAN_TYPE_FORWARDERS and dp.id == 0xa:
        eth_src = "08:00:27:e1:e4:83"
    elif dp.id in LAN_TYPE_FORWARDERS and dp.id == 0xc:
        eth_src = "08:00:27:52:fb:7d"

    ##If no src_mac was provided we generate one from Datapath ID of forwarder that recieved message
    ##If Datapath ID starts with zeros we cannot use it as legit MAC address
    ##Second hex digit must be 2 to indicate localy administered non-multicast address
    if eth_src == None:
        str_hex_dpid = str(hex(dp.id)).rstrip('L').lstrip('0x')
        if len(str_hex_dpid) < 11:
            eth_src ='02'
            for i in range(10-len(str_hex_dpid)):
                eth_src += '0'
            eth_src += str_hex_dpid
        else:
            eth_src = dp.id

    eth = ethernet.ethernet(eth_dst, eth_src, ether.ETH_TYPE_ARP)
    arp_req = arp.arp_ip(arp_code, eth_src, ip_sender, eth_target, ip_target)

    pkt = packet.Packet()
    pkt.add_protocol(eth)
    pkt.add_protocol(arp_req)
    pkt.serialize()
    actions=[parser.OFPActionOutput(port_out)]
    out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=pkt.data)
    dp.send_msg(out)


def _icmp_send(dp, port_out, ip_src=DISCOVERY_IP_SRC, ip_dst=DISCOVERY_IP_DST,
               eth_src='02:b0:00:00:00:b5', eth_dst='02:bb:bb:bb:bb:bb',
               icmp_type=8, icmp_code=0):
    """
    Generates ICMP packet and sends it out of 'port_out' on forwarder 'dp'

    Keyword arguments:
        dp -- Datapath
        port_out -- Port on forwarder (dp) used to spit out packet
        ip_src -- IP address of sender
        ip_dst  -- IP address of recipient
        eth_src -- Ethernet address of source (Default is 02:b0:00:00:00:b5 because none wanted to have 0xb00b5 as experimenter ID)
        eth_dst -- Ethernet destiation address (probably to be reworked)
        icmp_type -- ICMP type, default is 8 which is Echo
        icmp_code -- ICMP code, default is 0 which is No Code

    """

    ofp = dp.ofproto
    parser = dp.ofproto_parser
    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(ethertype=0x0800,
                                       dst=eth_dst,
                                       src=eth_src))

    pkt.add_protocol(ipv4.ipv4(dst=ip_dst,
                               src=ip_src,
                               proto=1))

    ##Latency measurement
    my_clock = str(time.clock())

    ##TODO: Rework payload and codes to properly work with Fragmentation needed
    pkt.add_protocol(icmp.icmp(type_=icmp_type,
                               code=icmp_code,
                               csum=0,
                               data=icmp.echo(1,1,"{'dpid' : "+str(dp.id)+",'port_out' : "+str(port_out)+",'clock' : "+my_clock+"}")))
    pkt.serialize()
    data=pkt.data
    actions=[parser.OFPActionOutput(port_out,0)]
    out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=data)
    ##LOG.debug('***ICMP DEBUG*** Sending ICMP with Payload: ' + "{'dpid' : "+str(dp.id)+",'port_out' : "+str(port_out)+",'clock' : "+my_clock+"}" )
    dp.send_msg(out)


def _icmp_parse_payload(pkt):
    """
    Used to parse payload of ICMP packets used for self-discovery which contains dictionary

    Keyword arguments:
        pkt -- ICMP paket
    """

    payload = ''
    icmp_pkt = pkt.get_protocol(icmp.icmp)
    for char in icmp_pkt.data.data:
        payload+=(chr(char))
    parsed_payload = ast.literal_eval(payload.rstrip('\0'))
    return(parsed_payload)


def get_tid():
    """
    Generator of Tunnel identifiers (in MAC addr. format)

    """

    mac_char='0123456789abcdef'
    mac_addr='02:'
    available=0
    while available == 0:
        for i in range(5):
            for y in range(2):
                mac_addr = mac_addr + random.choice(mac_char)
            mac_addr = mac_addr + ':'

        mac_addr = mac_addr[:-1]
        if mac_addr not in TID_POOL:
            available = 1
    TID_POOL.append(mac_addr)
    return(mac_addr)





class PDPContext:
    """
    Class used to store active PDP CNTs

    Keyword arguments:

    bvci -- BSSGP Virtual Connection Identifier
    tlli -- Temporary Logical Link Identifier
    sapi -- Service Access Point Identifier
    nsapi -- Network Service Acces Point Indetifier
    tid_out -- Tunnel identifier this context uses to get to APN
    tid_in -- Tunnel identifier this context uses on the way back IN
    """

    def __init__(self, bvci, tlli, sapi, nsapi, tid_out, tid_in, client_ip, imsi, drx_param):
        self.bvci = bvci
        self.tlli = tlli
        self.sapi = sapi
        self.nsapi = nsapi
        #TODO: QoS a tunnel treba premysliet
        self.tid_out = tid_out
        self.tid_in = tid_in
        self.client_ip = client_ip
        self.imsi = imsi
        self.drx_param = drx_param


class GPRSControll(app_manager.RyuApp):
    """
    Main class of controller application
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(GPRSControll, self).__init__(*args, **kwargs)

        global dpset
        dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = dpset
        self.data['waiters'] = self.waiters
        mapper = wsgi.mapper

        ##RestCall reffers to class that holds methods/functions (WTF python calls them),
        ##that can be called via REST interface
        wsgi.registory['RestCall'] = self.data

        ##path holds string that is used to adress REST calls
        ##e.g.: localhost:8080/gprs/info/whatever
        path = '/gprs'

        ##mapper.connect defines which method is executed for particular REST call
        uri = path + '/info/{opt}'
        mapper.connect('stats',uri,
                       controller=RestCall, action='info',
                       conditions=dict(method=['GET']))


        uri = path + '/pdp/{cmd}'
        mapper.connect('stats',uri,
                       controller=RestCall, action='mod_pdp',
                       conditions=dict(method=['GET']))

        uri = '/topology/dump'
        mapper.connect('stats',uri,
                       controller=RestCall, action='dump_topology',
                       conditions=dict(method=['GET', 'HEAD']))

        uri = '/measurement/set/{interval}'
        mapper.connect('stats', uri,
                       controller=RestCall, action='set_measurement_interval',
                       conditions=dict(method=['GET', 'HEAD']))

        uri = '/TE/classone/set/{dscps}'
        mapper.connect('stats', uri,
                       controller=RestCall, action='set_class_one',
                       conditions=dict(method=['GET', 'HEAD']))
        uri = '/TE/classtwo/set/{dscps}'
        mapper.connect('stats', uri,
                       controller=RestCall, action='set_class_two',
                       conditions=dict(method=['GET', 'HEAD']))
        uri = '/TE/latencies/set/{thresholds}'
        mapper.connect('stats', uri,
                       controller=RestCall, action='set_latencies',
                       conditions=dict(method=['GET', 'HEAD']))

        #Testing
        uri =  '/test/info'
        mapper.connect('stats', uri,
                        controller=RestCall, action='test_info',
                        conditions=dict(method=['GET']))

        #This creates a plain MAC tunnel for the purpose of WMCN testing
        uri = '/test/create/mactunnel/{source}/{destination}'
        mapper.connect('stats',uri,
                        controller=RestCall, action='create_mac_tunnel',
                        conditions=dict(method=['GET']))

        ## DNS ressolution of IP address of PDP CNTs if it's not already defined
        ## !!! MAKE SURE you have valid DNS entry available in /etc/hosts or DNS server !!!
        for apn in APN_POOL:
            if apn.ip_addr==None:
                try:
                    ip_addr = str(socket.gethostbyname(apn.name))
                    apn.ip_addr = ip_addr
                    LOG.debug('Resolved APN '+apn.name+' : '+apn.ip_addr)
                except socket.gaierror:
                    LOG.warning('Error while resolving apn name "'+apn.name+'"' )
                    continue


        # start measurement
        threading.Timer(MEASUREMENT_CHECK, self.periodic_measurement).start()

    def periodic_measurement(self):
        if MEASUREMENT_INTERVAL > 0:
            # LOG.debug (topo.DynamicGraph.nodes())
            # LOG.debug (topo.DynamicGraph.edges())

            ifnum = nx.get_edge_attributes(topo.DynamicGraph,'interf')
            my_lat = nx.get_edge_attributes(topo.DynamicGraph,'lat')
            my_util = nx.get_edge_attributes(topo.DynamicGraph,'util')
            my_update = nx.get_edge_attributes(topo.DynamicGraph,'upt')
            my_latVar = nx.get_edge_attributes(topo.DynamicGraph,'pdv')
            my_upl = nx.get_edge_attributes(topo.DynamicGraph,'upl')

            # send port stats requests
            for fwder in topo.DynamicGraph.nodes():
                try:
                    self._port_stats(dpset.get(fwder))
                except:
                    # LOG.debug('EXCEPT MNGR: Node: ' + str(fwder) + ' has thrown an exception. "Not possible to send stats request"')
                    continue

            ## Print debug only for inner links
            for edg in topo.DynamicGraph.edges():
                try:
                    # If it is measured link...
                    if my_lat[edg] != NON_MEASURED_LINK:

                        ## Link criticality COMPUTATION
                        my_upl[edg] =  0
                        for tun in TUNNELS:
                            if edg in tun.po_edges or edg in tun.pi_edges:
                                my_upl[edg] += 1


                        ## Loss computation
                        loss = self.loss_update(edg[0], edg[1], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

                        ## dpset used to get datapath object of the forwarder
                        ## send measurements pkts
                        _icmp_send(dpset.get(edg[0]), ifnum[edg], DISCOVERY_IP_SRC, DISCOVERY_IP_DST)
                        LOG.debug("MEASURE MNGR: Link " + str(edg) + " port " + str(ifnum[edg])+ " Latency " + str("{:8.3f}".format(1000*my_lat[edg]))
                                  + " LatencyVar: " + str("{:8.3f}".format(1000*my_latVar[edg]))
                                  + " Update " + str(my_update[edg]) + " Utilization: " + str("{:5.0f}".format(my_util[edg])) + " B/s (" + str(MEASUREMENT_INTERVAL)
                                  + " sec average) Loss: " + str(loss) + " UPL: " + str(my_upl[edg]))


                except:
                    LOG.debug('EXCEPT MNGR: edg[0]: ' + str(edg[0]) + ' has thrown an exception. "Not possible to send latency measurement ICMP"' + str(sys.exc_info()[0]))



            ## tunnel metrics update with usage of previously created edges
            for tun in TUNNELS:
                tun.path_out_lat = self.tunnel_latency(tun.po_edges, my_lat)
                tun.path_out_latVar = self.tunnel_latency(tun.po_edges, my_latVar)
                tun.path_in_lat = self.tunnel_latency(tun.pi_edges, my_lat)
                tun.path_in_latVar = self.tunnel_latency(tun.pi_edges, my_latVar)


                self.tunnel_loss_update(tun)

                tun.util_out = 0
                tun.util_in = 0
                for edg in tun.po_edges:
                    if edg in my_util:
                        if tun.util_out < my_util[edg]:
                            tun.util_out = my_util[edg]
                        if tun.upl < my_upl[edg]:
                            tun.upl = my_upl[edg]
                for edg in tun.pi_edges:
                    if edg in my_util:
                        if tun.util_in < my_util[edg]:
                            tun.util_in = my_util[edg]
                        if tun.upl < my_upl[edg]:
                            tun.upl = my_upl[edg]

                util_out_perc = tun.util_out * 8 / tun.max_util_out
                util_in_perc = tun.util_in * 8 / tun.max_util_in
                
                if util_out_perc > 1:
                    util_out_perc = 1
                    tun.util_out = tun.max_util_out / 8
                if util_in_perc > 1:
                    util_in_perc = 1
                    tun.util_in = tun.max_util_in / 8

                tun.util_out_perc = util_out_perc
                tun.util_in_perc = util_in_perc

                LOG.debug("MEASURE MNGR: Tunnel path: " + str(tun.po_edges) + " Latency: " + str("{:8.3f}".format(1000*tun.path_out_lat)) + " LatencyVariation:" + str("{:8.3f}".format(1000*tun.path_out_latVar))
                          + " BW: " + str(tun.util_out * 8) + "/" + str(tun.max_util_out) + " which is: " + str(tun.util_out_perc * 100) + " %")
                LOG.debug("MEASURE MNGR: Tunnel path: " + str(tun.pi_edges) + " Latency: " + str("{:8.3f}".format(1000*tun.path_in_lat)) + " LatencyVariation:" + str("{:8.3f}".format(1000*tun.path_in_latVar))
                          + " BW: " + str(tun.util_in * 8) + "/" + str(tun.max_util_in) + " which is: " + str(tun.util_in_perc * 100) + " %")

            threading.Timer(MEASUREMENT_INTERVAL, self.periodic_measurement).start()
        else:
            LOG.debug("MEASURE MNGR: Not measuring as measurement interval is " + str(MEASUREMENT_INTERVAL))
            threading.Timer(MEASUREMENT_CHECK, self.periodic_measurement).start()

    def tunnel_latency(self, edges, edgesParams):
        Sum = 0
        for edg in edges:
            Sum += edgesParams[edg]
        return Sum

    def tunnel_loss_update(self, tun):
        my_loss = nx.get_edge_attributes(topo.DynamicGraph, 'loF')
        tun.loss = False
        for edg in tun.po_edges:
            if edg in my_loss:
                if my_loss[edg] == True:
                    tun.loss = True
        for edg in tun.pi_edges:
            if edg in my_loss:
                if my_loss[edg] == True:
                    tun.loss = True

    # dps - datapath source
    # dpd - datapath destination
    # currentDate - date string in "%Y-%m-%d %H:%M:%S" format
    def loss_update(self, dps, dpd, currentDate):
        loss = False
        deltaLastUpdate = datetime.datetime.strptime(currentDate, "%Y-%m-%d %H:%M:%S") - datetime.datetime.strptime(topo.StaticGraph[dps][dpd]['upt'], "%Y-%m-%d %H:%M:%S")
        deltaTimeout = datetime.timedelta(seconds=(MEASUREMENT_INTERVAL + MEASUREMENT_TIMEOUT))
        # if measurement packet is not received in less than MEASUREMENT_TIMEOUT seconds, consider it as lost on link
        if deltaLastUpdate < deltaTimeout:
            loss = False
            topo.StaticGraph[dps][dpd]['loD'] = 0;
        else:
            loss = True
            topo.StaticGraph[dps][dpd]['loD'] += 1;

        topo.StaticGraph[dps][dpd]['loF'] = loss
        return loss

    def utilization_update(self, dpid, port_no, tx_b):
        #dp = dpset.get(dpid)

        #LOG.debug(dpset.get(dpid).ports)
        #for p in dp.ports:
            #LOG.debug('Port: ' + str(dp.ports[p]))
            #Maximum actual speed of the port
            #LOG.debug('current speed: ' + str(dp.ports[p].curr_speed))

        # received port stats and need to know dpid of ohter FWDer on port
        for suc in topo.DynamicGraph.successors(dpid):
            if topo.DynamicGraph[dpid][suc]['interf'] == port_no:
                if topo.DynamicGraph[dpid][suc]['util'] == NON_MEASURED_LINK:
                    #LOG.debug('UTIL MNGR: update edge ' + str(dpid)+ ' ' + str(suc) + ' with tx_b: ' + str(tx_b / MEASUREMENT_INTERVAL) )
                    topo.StaticGraph[dpid][suc]['tx_b'] = tx_b
                    topo.StaticGraph[dpid][suc]['util'] = tx_b / MEASUREMENT_INTERVAL
                else:
                    #LOG.debug('UTIL MNGR: update edge ' + str(dpid)+ ' ' + str(suc) + ' with tx_b: ' + str((tx_b - topo.DynamicGraph[dpid][suc]['util']) / MEASUREMENT_INTERVAL) )
                    topo.StaticGraph[dpid][suc]['util'] = (tx_b - topo.StaticGraph[dpid][suc]['tx_b']) / MEASUREMENT_INTERVAL
                    topo.StaticGraph[dpid][suc]['tx_b'] = tx_b
        topo.reload_topology()

    def _port_stats(self, datapath):
        #LOG.debug('MEASURE MNGR: send stats request to forwarder: %d', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        for stat in sorted(body, key=attrgetter('port_no')):
            self.utilization_update(dpid, stat.port_no, stat.tx_bytes)

    # universal method for meters handling
    def mod_meter_entry(self, dp, meter,meter_id, cmd):

        flags_convert = {'KBPS': dp.ofproto.OFPMF_KBPS,
                         'PKTPS': dp.ofproto.OFPMF_PKTPS,
                         'BURST': dp.ofproto.OFPMF_BURST,
                         'STATS': dp.ofproto.OFPMF_STATS}

        flags = 0
        if 'flags' in meter:
            meter_flags = meter['flags']
            if not isinstance(meter_flags, list):
                meter_flags = [meter_flags]
            for flag in meter_flags:
                if flag not in flags_convert:
                    LOG.error('Unknown meter flag: %s', flag)
                    continue
                flags |= flags_convert.get(flag)



        bands = []
        for band in meter.get('bands', []):
            band_type = band.get('type')
            rate = int(band.get('rate', 0))
            burst_size = int(band.get('burst_size', 0))
            if band_type == 'DROP':
                bands.append(
                    dp.ofproto_parser.OFPMeterBandDrop(rate, burst_size))
            elif band_type == 'DSCP_REMARK':
                prec_level = int(band.get('prec_level', 0))
                bands.append(
                    dp.ofproto_parser.OFPMeterBandDscpRemark(
                        rate, burst_size, prec_level))
            elif band_type == 'EXPERIMENTER':
                experimenter = int(band.get('experimenter', 0))
                bands.append(
                    dp.ofproto_parser.OFPMeterBandExperimenter(
                        rate, burst_size, experimenter))
            else:
                LOG.error('Unknown band type: %s', band_type)

        msg = dp.ofproto_parser.OFPMeterMod(
            dp, cmd, flags, meter_id, bands)

        dp.send_msg(msg)

    # universal method, add, delete modify flows ...
    def mod_flow(self, dp, cookie=0, cookie_mask=0, table_id=0,
                 command=None, idle_timeout=0, hard_timeout=0,
                 priority=0xff, buffer_id=0xffffffff, match=None,
                 actions=None, inst_type=None, out_port=None,
                 out_group=None, flags=0, inst=None):

        if command is None:
            command = dp.ofproto.OFPFC_ADD

        if inst is None:
            if inst_type is None:
                inst_type = dp.ofproto.OFPIT_APPLY_ACTIONS

            inst = []
            if actions is not None:
                inst = [dp.ofproto_parser.OFPInstructionActions(
                    inst_type, actions)]

        if match is None:
            match = dp.ofproto_parser.OFPMatch()

        if out_port is None:
            out_port = dp.ofproto.OFPP_ANY

        if out_group is None:
            out_group = dp.ofproto.OFPG_ANY

        m = dp.ofproto_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                         table_id, command,
                                         idle_timeout, hard_timeout,
                                         priority, buffer_id,
                                         out_port, out_group,
                                         flags, match, inst)

        dp.send_msg(m)


    def on_edge_inet_dp_join(self, dp, port, apn):
        """ Add special rules for forwader on edge (APN-side) of network

            Keyword arguments:
                dp -- datapath
                port -- ID of port with APN on the other side
                apn -- only for logging purposes
        """

        ofp = dp.ofproto
        parser = dp.ofproto_parser

        ##All ARP requests that come from APN are forwarded to Controller which then handle them
        LOG.debug('TOPO MNGR: Redirecting all ARP req from APN: ' + apn.name +  '  to controller by OFrule on forwarder: ' + str(dp.id))
        match = parser.OFPMatch(in_port=port, eth_type=0x0806, arp_op=1)
        actions = [ parser.OFPActionOutput(ofp.OFPP_CONTROLLER) ]
        inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
        req = parser.OFPFlowMod(datapath=dp, priority=10, match=match, instructions=inst)
        dp.send_msg(req)

    def on_inner_dp_join(self, dp):
        """ Add new inner (BSS side) forwarder joined our network.

        Keyword arguments:
            dp -- datapath

        TODO:
          VGSN inside our SDN network -- routing of GPRS-NS traffic

        """
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        #Deletion of already existing OF flows
        LOG.debug('TOPO MNGR: Deleting flow table configuration of newly added forwarder ID: ' + str(dp.id) )
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE))
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE, table_id=OF_GPRS_TABLE))
        #TODO: Shall we wipe-out OFconfig data as well?


        ##########################
        ## Main table (0)
        ## TODO:change to echo only!

        ## Networks self-discovery using icmp messages
        ## Redirect all pings with ipv4_dst=DISCOVERY_IP_DST to controller
        LOG.debug('TOPO MNGR: Installing ICMP topology discovery flows on forwarder: ' + str(dp.id))
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=1, icmpv4_type=8, icmpv4_code=0, ipv4_dst=DISCOVERY_IP_DST)
        actions = [ parser.OFPActionOutput(ofp.OFPP_CONTROLLER) ]
        ##TEST SHAPING ON FWD 11 on port 1 - trying to shape also measurement packets
        self.add_flow(dp, 100, match, actions, 0)

        ##Controller uses ARP to resolve mac_addresses of APNs
        ##All arp replies with target IP of DISCOVERY_ARP_IP are redirected to controller

        ## FIXED: All ARPs replies are redirected to the controller regardless of the target IP
        ##
        ## TODO:  In general we should reply only to ARPs from the APNs subnet, and per APN basis (from the configuration)

        LOG.debug('TOPO MNGR: Installing ARP APN discovery flows on forwarder: ' + str(dp.id))
        match = parser.OFPMatch(eth_type=0x0806, arp_op=2, )
        actions = [ parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]
        self.add_flow(dp, 100, match, actions)


        # We match only ethertype, that means all IP packed data should be match
        # It is some kind of flow of last resort, therefore it has small priority
        if dp.id in LAN_TYPE_FORWARDERS:
            LOG.debug('TOPO MNGR: Forwarder: ' + str(dp.id) + 'is a LAN edge forwarder, installing additional rules' )
            match = parser.OFPMatch(eth_type=0x0800)
            actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]
            self.add_flow(dp, 2, match, actions)

        rate = 500
        # all fwds have set of meters
        for i in range(0,11):
            meter_id = i
            if i == 0:
                rate = 100000000
            elif i % 2 == 0:
                rate = 1000
            else:
                rate = 2000
            # KBPS is actually kbps
            meter = {'meter_id': meter_id, 'flags': 'KBPS',
                     'bands': [{'type': 'DROP', 'rate': rate}]}
            self.mod_meter_entry(dp, meter, meter_id, dp.ofproto.OFPMC_ADD)
            LOG.debug("FLOW MNGR: Added METER ID: " + str(i) + " with rate: " + str(rate) + " to FWD ID: " + str(dp.id) )


        ##Following rules are applied only on forwarders bellonging to BSS_EDGE_FORWARDER group
        ##Rules are applied based on priority of match (highest priority first)
        if dp.id in BSS_EDGE_FORWARDER:

            LOG.debug('TOPO MNGR: Forwarder: ' + str(dp.id) + ' is an access edge forwarder, installing aditional rules')
            ## UDP 23000 is GPRS-NS and all packets that match this are forwarded to OF_GPRS_TABLE flow table
            inst = [ parser.OFPInstructionGotoTable(OF_GPRS_TABLE) ]
            match = parser.OFPMatch(eth_type=0x0800,ip_proto=inet.IPPROTO_UDP, udp_dst=VGSN_PORT)
            req = parser.OFPFlowMod(datapath=dp, priority=200, match=match, instructions=inst)
            dp.send_msg(req)

            ## VGSN_PHY and BSS_PHY ports are bridged -- DHCP, ARP, Abis & stuff
            ## XXX: what if vGSN is not on same forwarder as BSS
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
            ## OF_GPRS-TABLE (2)
            ##TODO: BSS <-> vGSS separate tunnel for communication!
            ##TODO: deletion, modification od  PDP CNT

            ## if packet is not first segment  of user data packet (IS part of sndcp fragmented packet) it's DROPED
            match = parser.OFPMatch( sndcp_first_segment=0 )
            actions = [ ]
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=200, match=match, instructions=inst)
            dp.send_msg(req)

            ## if packet is first segment of SNDCP packet with more than one segment, it's forwarded to controller
            ## when controller recieves such packet it sends ICMP fragmentation_needed to its sender and drops original
            match = parser.OFPMatch( sndcp_first_segment=1, sndcp_more_segments=1 )
            actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER) ]
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=200, match=match, instructions=inst)
            dp.send_msg(req)

            ##if it's SNDCP packet taht still wasnt matched (rules with higher priority are inserted on PDP CNT activation)
            ##we assume it's packet of unknown PDP CNT and we DROP it
            match = parser.OFPMatch( sndcp_first_segment=1 )
            actions = [ ]
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=1, match=match, instructions=inst)
            dp.send_msg(req)

            ##Everything else is Signalzation and is forwarded either to BSS or vGSN
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

    @set_ev_cls(ofp_event.EventOFPPacketIn)
    def _packet_in(self, ev):
        """
        This method handles packets that arrive directly to Controller
        """

        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = ev.msg.match

        ##SNDCP packet with multiple fragments recieved - print warning, send ICMP fragmentation needed
        ##TODO: Not WOrking correctly
        ## File "/usr/local/lib/python2.7/dist-packages/ryu/ofproto/ofproto_v1_3_parser.py", line 746, in __getitem__
        ## return dict(self._fields2)[key]
        ## KeyError: 'udp_dst'

        # if (match['eth_type'] == 0x0800 and match['ip_proto'] == inet.IPPROTO_UDP
        #     and match['udp_dst'] == VGSN_PORT and match['sndcp_first_segment'] == 1
        #     and match['sndcp_more_segments'] == 1):
        #     _icmp_send(dp,match['in_port'],match['ipv4_dst'],match['ipv4_src'],match['eth_dst'],match['eth_src'],icmp_type=3,icmp_code=4)
        #     LOG.warning('WARNING: Device with IP: '+match['ipv4_src']+' sent fragmented sndcp packet')
        #     return

        ##ARP request recieved - send 'I'm here' response
        if match['eth_type'] == 0x0806 and match['arp_op'] == 1:
            LOG.debug("ARP request accepted")
            _arp_send(dp=dp, port_out=match['in_port'], arp_code=2, eth_dst=match['eth_src'], eth_target=match['arp_sha'],
                      ip_target=match['arp_spa'], ip_sender=match['arp_tpa'])
            LOG.debug('Reply to '+match['arp_spa'] +': Host '+match['arp_tpa']+' is at forwarder '+str(dp.id) + " with ethX source MAC address")
            return

        ##ARP response with target_ip==DISCOVERY_ARP_IP recieved - we found APN
        #
        # FIXED: All ARP responses are replied, regardless of the target IP
        #
        # TODO : At this point only ARPs belonging to the APNs networks subnet should
        #        be answered
        if match['eth_type'] == 0x0806 and match['arp_op'] == 2:
            LOG.debug('TUNNEL MNGR: ARP response with target APN discovery IP recieved at controller, processing for APN extraction')
            pkt = packet.Packet(array.array('B', ev.msg.data))
            arp_pkt=pkt.get_protocol(arp.arp)
            apn_ip = arp_pkt.src_ip
            apn_mac= arp_pkt.src_mac
            port = match['in_port']

            ##Search for apn in APN_POOL to add mac addr. and update topology
            for sApn in APN_POOL:
                if sApn.ip_addr == apn_ip:
                    LOG.debug('Recieved ARP response was from ' + sApn.name + ' APN')
                    sApn.eth_addr = apn_mac
                    sApn.port = port
                    sApn.dpid = dp.id
                    # Links towards APNs will not be measured
                    topo.add_link(dp.id,str(sApn.name),port)
                    topo.add_link(str(sApn.name),dp.id,0)
                    topo.reload_topology()
                    LOG.debug('TUNNEL MNGR: APN '+str(sApn.name)+' found at forwarder: '+str(dp.id)+', port: '+str(port) + ' by ARP search')

                    ##Add special rules to edge forwarder
                    self.on_edge_inet_dp_join(dp, port, sApn)

                    # FIX: We do not handle bss as a special APN
                    #      For greater extensibility, BSS/UTRAN/LAN APNs (exit/enter) points
                    #      will be handled in a generic manner
                    #
                    ##Create MAC-tunnels between APN and all BSSs
                    #for bss in BSS_POOL:
                    #    self.add_tunnel(bss,apn)
                    #break

                    ### WMNC: In this case, we are not making tunnels between
                    #          two types of ingress/egress point, but actually same type

                    for dApn in APN_POOL:
                        # we are cycling through all possible APNs, looking for different APN tupples
                        # with filled HW addresses (already found by APN search)
                        if sApn != dApn and dApn.eth_addr != None:
                            LOG.debug('TUNNEL MNGR: Different APNs with filled HW address found, lets find out if there is tunnel between them')

                            paths = False
                            try:
                                paths = nx.all_simple_paths(topo.DynamicGraph, source=sApn.name, target=dApn.name)
                            except:
                                LOG.debug('TUNNEL MNGR: No path between: ' + sApn.name + ' and ' + dApn.name + '. Retry when next APN discovered.')

                            LOG.debug('TUNNEL MNGR: These are the paths between them (possible tunnels):')
                            if paths:
                                for path in paths:
                                    LOG.debug('TUNNEL MNGR: Calling add_plainMacTunnel for ' + sApn.name + ' and ' + dApn.name + ' with path: ' + str(path))
                                    self.add_plainMacTunnel(sApn, dApn, path)
                            else:
                                LOG.debug('TUNNEL MNGR: PATHS == 0 ????????????????')


            return

        ##ICMP echo with dst_ip==DISCOVERY_IP_DST recieved - new link between forwarders is up
        if match['eth_type'] == 0x0800 and match['ipv4_dst'] == DISCOVERY_IP_DST and match['ip_proto'] == 1:
            #LOG.debug('TOPO MNGR: ICMP echo recieved at controller, processing for link extraction or latency measurement')

            pkt = packet.Packet(array.array('B', ev.msg.data))

            ##Discovery pings carry information about sending datapath in payload of icmp packet
            ##these information are in Dictionary format, we parse the out with _icmp_parse_payload() method
            body = _icmp_parse_payload(pkt)
            neighbourDPID=body['dpid']
            neighbourPort=body['port_out']

            ## measurement
            ## currentClock moved way up to improve precision
            receivedClock=float(body['clock'])
            currentClock = time.clock()
            latency = currentClock - receivedClock

            currentDate = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            ##Update latency or add new edges to topology.
            if topo.DynamicGraph.has_edge(dp.id, neighbourDPID) and topo.DynamicGraph.has_edge(neighbourDPID, dp.id):
                topo.StaticGraph[neighbourDPID][dp.id]['pdv'] = topo.StaticGraph[neighbourDPID][dp.id]['lat'] - latency
                topo.StaticGraph[neighbourDPID][dp.id]['lat'] = latency
                topo.StaticGraph[neighbourDPID][dp.id]['upt'] = currentDate
                #topo.StaticGraph[neighbourDPID][dp.id]['upt'] = currentDate
                loss = self.loss_update(neighbourDPID, dp.id, currentDate)
                #LOG.debug('TOPO MNGR: Updating latency ' + str(latency) + ' and date ' + str(currentDate) + ' LOSS: ' + str(loss))
                topo.reload_topology()
            else:
                ##  latency not correct for both directions when adding links
                ##  update occurs on receive of next measurement packet from oposite direction
                topo.add_link(dp.id, neighbourDPID, ev.msg.match['in_port'], latency, currentDate)
                topo.add_link(neighbourDPID, dp.id, neighbourPort , latency, currentDate)
                LOG.debug('TOPO MNGR: Topology changed: New link between forwarder ID '+str(dp.id)+ ' via port ' + str(ev.msg.match['in_port'])
                          +' and forwarder ID '+str(neighbourDPID)+ ' via port ' + str(neighbourPort) + ' was discovered.')

                topo.reload_topology()
                ## retry to create tunnels
                ## find better paths between APNs
                for sApn in APN_POOL:
                    for dApn in APN_POOL:
                        if sApn != dApn:
                            LOG.debug('TOPO MNGR: Topology changed: trying to re-build inactive tunnel between:' + sApn.name + ' and ' + dApn.name)
                            paths = False
                            try:
                                paths = nx.all_simple_paths(topo.DynamicGraph, source=sApn.name, target=dApn.name)
                            except:
                                LOG.debug('No path between: ' + sApn.name + ' and ' + dApn.name + '. Retry when next fwd connects.')

                            LOG.debug('TUNNEL MNGR: These are the paths between them (possible tunnels):')
                            if paths:
                                for path in paths:
                                    LOG.debug('TUNNEL MNGR: Calling add_plainMacTunnel for ' + sApn.name + ' and ' + dApn.name + ' with path: ' + str(path))
                                    self.add_plainMacTunnel(sApn, dApn, path)
                            else:
                                LOG.debug('TUNNEL MNGR: PATHS == 0 ????????????????')
            return

        # flow of last resort (process for routing)
        if match['eth_type'] == 0x0800:
            # LOG.debug('*****************Flow of last resort matched(plain IP), process for routing********'
            #           + ' match[ipv4_dst]: ' + str(match['ipv4_dst'] + ' match[ipv4_src]: ' + str(match['ipv4_src']) + ' DSCP: ' + str(match['ip_dscp'])))
            ## Not very proud of myself, but it will do the trick
            ## Turbo lumberjack routing logic
            ## TODO: Implement a longest prefix match routing

            candidates = []

            for source, destination, ip_dscp in routesList:
                if ((source == match['ipv4_dst'] and destination == match['ipv4_src']) or (source == match['ipv4_src'] and destination == match['ipv4_dst'])) and ip_dscp == match['ip_dscp']:
                    # LOG.debug('ROUTING: route source: ' + str(source) + 'destination: ' + str(destination)
                    #           + ' match[ipv4_dst]: ' + str(match['ipv4_dst'])
                    #           + ' match[ipv4_src]: ' + str(match['ipv4_src']) + ' DSCP: ' + str(ip_dscp)
                    #           + ' already exists, aborting addition of new route')
                    return

            for tunnel in TUNNELS:
                if (tunnel.sApn.ip_addr == match['ipv4_dst'] and tunnel.dApn.ip_addr == match['ipv4_src']) or (tunnel.sApn.ip_addr == match['ipv4_src'] and tunnel.dApn.ip_addr == match['ipv4_dst']):
                    LOG.debug('ROUTING: Tunnel candidate found in list of tunnels. Adding tunnel path: ' + str(tunnel.po_edges) + ' to candidates.')
                    candidates.append(tunnel)

            trafficClass = self.TC_selection(match['ip_dscp'])

            if len(candidates) == 0:
                LOG.debug('ROUTING: match[ipv4_dst]: ' + str(match['ipv4_dst'])
                          + ' match[ipv4_src]: ' + str(match['ipv4_src']) + ' DSCP: ' + str(match['ip_dscp']))
                LOG.debug('ROUTING: ERROR, NO feasible tunnels for such route.')
                return

            LOG.debug('Looking for tunnels: DST_IP: ' + match['ipv4_dst'] + ' SRC_IP: ' + match['ipv4_src'] + ' DSCP: ' +  str(match['ip_dscp']) + '(traffic class: ' + str(trafficClass) + ')' + ' Incoming from FWD: ' + str(dp.id))
            tunnel = self.tunnel_selection(trafficClass, candidates)
            LOG.debug('TE MNGR: Selected tunnel Path out: ' + str(tunnel.path_out_str) + ' meter_id: ' + str(tunnel.meter_id))

            dscp = match['ip_dscp']

            ## meter_id
            ## 2,4,6,8,10 = 500kbps, 1,3,5,7,9 = 1000kbps ...
            ## 0 = 100Gbps
            meter_id = tunnel.meter_id

            #
            # FIXME: incomplete set of rules installed on LAN Access forwarders
            # TODO : Philosophy of table IDs should be clarified, as now it total mess!!!
            # TODO : this should be done only once, from that moment, all user plane packets
            #        should travelse only forwarder and should not be sent to controller



            #WAY OUT
            dp = dpset.get(tunnel.sApn.dpid)
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = parser.OFPMatch (eth_type=0x0800, ipv4_dst=tunnel.dApn.ip_addr, ip_dscp=dscp)
            actions = [parser.OFPActionSetField(eth_src=tunnel.tid_in), parser.OFPActionSetField(eth_dst=tunnel.tid_out)]
            inst = [parser.OFPInstructionGotoTable(MAC_TUNNEL_TABLE), parser.OFPInstructionMeter(meter_id), parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = parser.OFPFlowMod(datapath=dp, priority=100, match=match, instructions=inst, table_id=INGRESS_TABLE)
            dp.send_msg(req)

            LOG.debug('ROUTING: Installing flow ON WAY OUT to forwarderID: ' + str(dp.id) + ',Table: ' + str(INGRESS_TABLE) + ' DP ID: ' + str(tunnel.dApn.dpid) + ' Tunel dApn IP addr: ' + str(tunnel.dApn.ip_addr) + ' Tunnel ID: ' + str(tunnel.tid_out))

            dp = dpset.get(tunnel.dApn.dpid)
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = parser.OFPMatch (eth_dst=tunnel.tid_out)
            actions = [parser.OFPActionSetField(eth_dst=tunnel.dApn.eth_addr), parser.OFPActionOutput(tunnel.path_out[-1].port_out)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = parser.OFPFlowMod(datapath=dp, priority=300, match=match, instructions=inst, table_id=ACCESS_ADAPTATION_TABLE_OUT)
            dp.send_msg(req)
            LOG.debug('ROUTING: Installing flow ON WAY OUT to forwarderID: ' + str(dp.id) + ',Table: ' + str(ACCESS_ADAPTATION_TABLE_OUT) + ' DP ID: ' + str(tunnel.dApn.dpid)+ ' Tunel ID: ' + str(tunnel.tid_out)+ ' dApn ETH addr: ' + str(tunnel.dApn.eth_addr))

            #WAY IN
            dp = dpset.get(tunnel.dApn.dpid)
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = parser.OFPMatch (eth_type=0x0800, ipv4_dst=tunnel.sApn.ip_addr, ip_dscp=dscp)
            actions = [parser.OFPActionSetField(eth_dst=tunnel.tid_in), parser.OFPActionSetField(eth_src=tunnel.tid_out)]
            inst =  [parser.OFPInstructionGotoTable(MAC_TUNNEL_TABLE), parser.OFPInstructionMeter(meter_id), parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = parser.OFPFlowMod(datapath=dp, priority=100, match=match, instructions=inst, table_id = INGRESS_TABLE)
            dp.send_msg(req)
            LOG.debug('ROUTING: Installing flow ON WAY IN to forwarderID: ' + str(dp.id) + ',Table: ' + str(INGRESS_TABLE) + ' DP ID: ' + str(tunnel.sApn.dpid) + ' Tunel dApn IP addr: ' + str(tunnel.sApn.ip_addr) + ' Tunnel ID: ' + str(tunnel.tid_in))


            dp = dpset.get(tunnel.sApn.dpid)
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = parser.OFPMatch (eth_dst=tunnel.tid_in)
            actions = [parser.OFPActionSetField(eth_dst=tunnel.sApn.eth_addr), parser.OFPActionOutput(tunnel.path_in[-1].port_out)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = parser.OFPFlowMod(datapath=dp, priority=300, match=match, instructions=inst, table_id=ACCESS_ADAPTATION_TABLE_OUT)
            dp.send_msg(req)
            LOG.debug('ROUTING: Installing flow ON WAY IN to forwarderID: ' + str(dp.id) + ',Table: ' + str(ACCESS_ADAPTATION_TABLE_OUT) + ' DP ID: ' + str(tunnel.sApn.dpid)+ ' Tunel ID: ' + str(tunnel.tid_in)+ ' sApn ETH addr: ' + str(tunnel.sApn.eth_addr))


            LOG.debug('ROUTING: Rules on access edge forwarders installed')
            LOG.debug('ROUTING: Adding route: DST_IP: ' + tunnel.dApn.ip_addr + ' SRC_IP: ' + tunnel.sApn.ip_addr + ' dscp: ' + str(dscp) + ' path out str: ' + tunnel.path_out_str )
            routesList.append( ( tunnel.sApn.ip_addr, tunnel.dApn.ip_addr, dscp) )

            parser = dp.ofproto_parser

            for dpid in LAN_TYPE_FORWARDERS:
                ## DUNNO why this rule with low priority still hits traffic which is also matched by rules with IP address matches
                ## Here I delete the rule, it is added on FWD when it connects to controoller
                LOG.debug('TOPO MNGR: Forwarder: ' + str(dpid) + ' is a LAN edge forwarder, deleting rules')
                dp = dpset.get(dpid)
                priority = 2
                match = parser.OFPMatch(eth_type=0x0800)
                actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]
                self.mod_flow(dp, command=dp.ofproto.OFPFC_DELETE_STRICT,
                              table_id=0, actions=actions,
                              match=match, priority=priority)

                LOG.debug('TOPO MNGR: Forwarder: ' + str(dp.id) + ' is a LAN edge forwarder, installing rules again :)')
                match = parser.OFPMatch(eth_type=0x0800)
                actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]
                self.add_flow(dp, 2, match, actions)


    def TC_selection(self, dscp):
        trafficClass = 3
        if dscp in CLASS_ONE:
            trafficClass = 1
        elif dscp in CLASS_TWO:
            trafficClass = 2
        return trafficClass


    def tunnel_selection(self, trafficClass, tunnels):
        LOG.debug('TE MNGR: Tunnel selection trafficClass: ' + str(trafficClass))
        candidates = []
        selectedTunnel = None
        upl = 1000
        if trafficClass == 3:
            util = 1
            for tunnel in tunnels:
                if tunnel.util_out_perc <= util and tunnel.util_in_perc <= util:
                    # looking for least full tunnel
                    if tunnel.util_out_perc >= tunnel.util_in_perc:
                        # this is not an error, we consider the more utilized direction as the indicator
                        util = tunnel.util_out_perc
                    else:
                        util = tunnel.util_in_perc
                    selectedTunnel = tunnel
            return selectedTunnel

        elif trafficClass == 2:
            for tunnel in tunnels:
                if tunnel.util_out_perc != 1 and tunnel.util_in_perc != 1:
                    # latency less than 1 sec and loss under 1 %
                    if tunnel.path_out_lat < CLASS_TWO_LAT and tunnel.path_in_lat < CLASS_TWO_LAT and tunnel.loss == False:
                        LOG.debug('TE MNGR: CLASS 2 Candidate found. Path out: ' + str(tunnel.path_out_str))
                        candidates.append(tunnel)
                    else:
                        LOG.debug('TE MNGR: Tunnel does not meet lat criteria for CLASS 2. Path out: ' + str(tunnel.path_out_str))
                else:
                    LOG.debug('TE MNGR: CLASS 2 Tunnel full. Path out: ' + str(tunnel.path_out_str))
            if len(candidates) == 0:
                LOG.debug('TE MNGR: Not possible to satisfy CLASS 2 needs... calling selection for CLASS 3.')
                selectedTunnel = self.tunnel_selection(trafficClass = 3, tunnels=tunnels)
            else:
                LOG.debug('TE MNGR: Candidates for CLASS 2 found ... looking for best UPL.')
                for tunnel in candidates:
                    if tunnel.upl < upl:
                        upl = tunnel.upl
                        selectedTunnel = tunnel
            return selectedTunnel

        else:
            # Traffic class 1:
            for tunnel in tunnels:
                if tunnel.util_out_perc != 1 and tunnel.util_in_perc != 1:
                    # latency less than 0.1 sec, variation under 0.02 sec and loss under 1 %
                    if tunnel.path_out_lat < CLASS_ONE_LAT and tunnel.path_in_lat < CLASS_ONE_LAT and abs(tunnel.path_out_latVar) < CLASS_ONE_LAT_VAR and abs(tunnel.path_in_latVar) < CLASS_ONE_LAT_VAR and tunnel.loss == False:
                        LOG.debug('TE MNGR: CLASS 1 Candidate found. Path out: ' + str(tunnel.path_out_str))
                        candidates.append(tunnel)
                    else:
                        LOG.debug('TE MNGR: Tunnel does not meet lat criteria for CLASS 1. Path out: ' + str(tunnel.path_out_str))
                else:
                    LOG.debug('TE MNGR: CLASS 1 Tunnel full. Path out: ' + str(tunnel.path_out_str))
            if len(candidates) == 0:
                LOG.debug('TE MNGR: Not possible to satisfy CLASS 1 needs... calling selection for CLASS 2.')
                selectedTunnel = self.tunnel_selection(trafficClass=2, tunnels=tunnels)
            else:
                LOG.debug('TE MNGR: Candidates for CLASS 1 found ... looking for best UPL.')
                for tunnel in candidates:
                    if tunnel.upl < upl:
                        upl = tunnel.upl
                        selectedTunnel = tunnel
            return selectedTunnel

    @set_ev_cls(dpset.EventDP, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def forwarder_state_changed(self, ev):
        """
        This method handles change of forwarders state

target        ev.enter is False  -- Forwarder got disconnected
        """


        dp = ev.dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser


        if ev.enter is True:
            # in plain MAC setup, this should install only ICMP and ARP re-route rules, watchout for hardcoded DP id
            self.on_inner_dp_join(dp)
	    ##For evry new forwarder we send out discovery ICMP packets out of every port except OFPP_CONTROLLER
            LOG.debug('TOPO MNGR: Forwarder: ' + str(dp.id) + ' saying hello to Unifycore Controller, Unifycore warmly welcomes you!')
            for port in dp.ports:
                if port != (ofp.OFPP_CONTROLLER):
                    LOG.debug('TOPO MNGR: Controller is sending topology discovery ICMPs to forwarder: ' + str(dp.id) + ', port: ' + str(port))
                    _icmp_send(dp,port,DISCOVERY_IP_SRC, DISCOVERY_IP_DST)

                    ##For evry new forwarder we send out discovery ARP packets out of every port except OFPP_CONTROLLER to find APN
                    for apn in APN_POOL:
                        if apn.ip_addr != None:
                            LOG.debug('TOPO MNGR: Forwarder: '+str(dp.id)+', port: '+ str(port)   + ' is looking for APN: ' + str(apn.name) +' at IP: '+str(apn.ip_addr)+' with ARP search source IP: ' + str(apn.arp_origin_ip))
                            _arp_send(dp=dp, port_out=port, arp_code=1, ip_target=apn.ip_addr, ip_sender=apn.arp_origin_ip)





        if ev.enter is False:
	    ##TODO: We need to scan if any tunnels were affected, and if so, if any PDP COntexts were affected
            ##JUST REMOVING NODE FROM TOPOLOGY ISNT ENOUGH!
            LOG.debug('TOPO MNGR: Forwarder: ' + str(dp.id) + ' is leaving topology. It was a pleasure for us!')
            topo.del_forwarder(dp.id)



    def add_plainMacTunnel(self, sApn, dApn, path):
        """
        This method is called when new APN is discovered to connect it with all BSS stations via MAC Tunnels
        Keyword arguments:
            _sApn_ -- usualy string representing BSS node in topology
            _dApn_ -- object of apn class representing APN in topology

        """

        sApn = sApn
        dApn = dApn
        tid_out = get_tid()
        tid_in  = get_tid()

        ##Attempt to find path between the two nodes
        ##If no path is found, tunnel is added to INACTIVE_TUNNELS and is attempted to recreate next time
        ##when new link between forwarders is up
        LOG.debug('TUNNEL MNGR: Searching for path between '+sApn.name+' and '+dApn.name )
        LOG.debug('TUNNEL MNGR: endpoints are: '+sApn.ip_addr+' and '+dApn.ip_addr)

        #PATH_OUT ---> from source to destination
        path_out = topo.build_path(path)
        # PATH_IN ---> from destination to source
        path_in  = topo.build_path(path[::-1])

        path_out_str = str(path)
        path_in_str = str(path[::-1])

        LOG.debug("TUNNEL MNGR: path_out_str: " + str(path_out_str))
        LOG.debug("TUNNEL MNGR: path_in_str: " + str(path_in_str))

        #for node in path_out:
        #    LOG.debug('TUNNEL MNGR: PATH_OUT dpid: ' + str(node.dpid) + ' port_out: ' + str(node.port_out))
        #for node in path_in:
        #    LOG.debug('TUNNEL MNGR: PATH_IN dpid: ' + str(node.dpid) + ' port_out: ' + str(node.port_out))

        for tun in TUNNELS:
            if (tun.path_out_str == path_out_str) or (tun.path_out_str == path_in_str) or (tun.path_in_str == path_out_str) or (tun.path_in_str == path_in_str):
                LOG.debug('TUNNEL MNGR: Such tunnel already exist. No rules will be installed.')
                return
            else:
                continue

        ## lets create edges for further computations
        fwds_out = path[1:-1]
        fwds_in = path[::-1][1:-1]
        po_edges = []
        pi_edges = []
        for k in fwds_out:
            for edg in topo.DynamicGraph.edges():
                try:
                    if edg[0] == k and edg[1] == fwds_out[fwds_out.index(k) + 1]:
                        po_edges.append(edg)
                except:
                    continue
        for k in fwds_in:
            for edg in topo.DynamicGraph.edges():
                try:
                    if edg[0] == k and edg[1] == fwds_in[fwds_in.index(k) + 1]:
                        pi_edges.append(edg)
                except:
                    continue


        ## !!!HACK!!! setting shaping in tunnels manually, shaping is on edge forwarders
        meter_id = 0
        rate = 100000000
        if len(po_edges) % 2 == 0:
            meter_id = list.pop(even_meters)
            rate = 500
        else:
            meter_id = list.pop(odd_meters)
            rate = 1000
        max_util = rate*1000 # to kbps

        LOG.debug("TUNNEL MNGR: meter id for this tunnel: " + str(meter_id) + " which shape it to: " + str(rate) + " kbps" )
        LOG.debug("TUNNEL MNGR: Path_out_edges: " + str(po_edges))
        LOG.debug("TUNNEL MNGR: Path_in_edges: " + str(pi_edges))


        LOG.debug('TUNNEL MNGR: Path_in and Path_out found, lets install OF rules on forwarders')
        ##Set forwarding rules for all but last forwarder on the way OUT
        ##On first forwarder on the way OUT these rules are placed into table MAC_TUNNEL_TABLE while on 'dumb' forwarders it goes to 0
        dp = dpset.get(path_out[0].dpid)
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_dst=tid_out)
        actions = [parser.OFPActionOutput(path_out[0].port_out)]
        self.add_flow(dp, 300, match, actions, MAC_TUNNEL_TABLE, meter_id)
        LOG.debug('TUNNEL MNGR: Rule for first forwarder on path_out installed, forwarderID: ' + str(dp.id) + ' OFPMatch(eth_dst=tid_out): ' + str(tid_out) + ' port_out: ' + str(path_out[0].port_out) )



        ##Rules for all 'dumb' forwardes on the way OUT
        for node in path_out[1:-1]:
            dp = dpset.get(node.dpid)
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_dst=tid_out)
            actions = [parser.OFPActionOutput(node.port_out)]
            self.add_flow(dp, 300, match, actions, INGRESS_TABLE)
            LOG.debug('TUNNEL MNGR: installed rule on dumb transport forwarder on path_out, forwarderID: ' + str(dp.id))


        ##Last forwarder on the way OUT needs to set eth_dst to eth_addr of APN otherwise it wont be processed
        dp = dpset.get(path_out[-1].dpid)
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_dst=tid_out)
        inst = [parser.OFPInstructionGotoTable(ACCESS_ADAPTATION_TABLE_OUT)]
        req = parser.OFPFlowMod(datapath=dp, priority=300, match=match, instructions=inst, table_id=INGRESS_TABLE)
        dp.send_msg(req)
        LOG.debug('TUNNEL MNGR: installed rule on last forwarder on the path_out, forwarderID: ' + str(dp.id))




        LOG.debug('TUNNEL MNGR: ---------')
        LOG.debug('TUNNEL MNGR: Way out done, proceeding to way in')
        LOG.debug('TUNNEL MNGR: ---------')




        ##Here comes tunnel for way IN
        ##On first forwarder on the way IN these rules are placed into table MAC_TUNNEL_TABLE while on 'dumb' forwarders it goes to INGRESS_TABLE
        dp = dpset.get(path_in[0].dpid)
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_dst=tid_in)
        actions = [parser.OFPActionOutput(path_in[0].port_out)]
        self.add_flow(dp, 300, match, actions, MAC_TUNNEL_TABLE, meter_id)
        LOG.debug('TUNNEL MNGR: Rule for first forwarder in path_in installed, forwarderID: ' + str(dp.id))

        ##Rules for 'dumb' forwarders
        for node in path_in[1:-1]:
            dp = dpset.get(node.dpid)
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_dst=tid_in)
            actions = [parser.OFPActionOutput(node.port_out)]
            self.add_flow(dp, 300, match, actions, INGRESS_TABLE)
            LOG.debug('TUNNEL MNGR: installed rule on dumb transport forwarder on path_in, forwarderID: ' + str(dp.id))

        ##Last forwarder on the way IN sends packet to table #4 where it's matched based on active PDP CNTs
        dp = dpset.get(path_in[-1].dpid)
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_dst=tid_in)
        inst = [ parser.OFPInstructionGotoTable(ACCESS_ADAPTATION_TABLE_OUT) ]
        req = parser.OFPFlowMod(datapath=dp, priority=300, match=match, instructions=inst, table_id=INGRESS_TABLE)
        dp.send_msg(req)
        LOG.debug('TUNNEL MNGR: installed rule on last forwarder on the path_in, forwarderID: ' + str(dp.id))

        TUNNELS.append(plainMacTunnel(sApn, dApn, tid_out, tid_in, path_out, path_in, path_out_str, path_in_str, po_edges, pi_edges, max_util, meter_id))
        LOG.debug('TUNNEL MNGR: NEW Tunnel between '+sApn.name+' and '+dApn.name + ' has been set up.')

    def add_flow(self, dp, priority, match, actions, table=0, meter_id=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionMeter(meter_id)]

        mod = parser.OFPFlowMod(datapath=dp, table_id=table, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)


class RestCall(ControllerBase):
    """
    This Class contains methods that can be executed via REST calls
    """

    def __init__(self, req, link, data, **config):
        super(RestCall, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    #WMNC testing
    #curl -X GET 127.0.0.1:8080/test/create/mactunnel/aa:aa:aa:aa:aa/bb:bb:bb:bb:b
    #more correct would be -X PUT
    def create_mac_tunnel(self, req, source, destination):
        LOG.debug(req)
        LOG.debug(source)
        LOG.debug(destination)
        return (Response('It works!'))






    #Testing
    def test_info(self,req):
        global dpset
        response = '<H1>Topology status DUMP</H1> </BR>'
        response += '<B>Dump created on: </B> ' + str(datetime.datetime.now())
        response += '</BR></BR><B>BSS edge forwarders list(decimal values):      </B> ' + str(BSS_EDGE_FORWARDER)
        response +=      '</BR><B>Internet edge forwarders list(decimal values): </B> ' + str(INET_EDGE_FORWARDER)

        response +=      '</BR><B>Active tunnels:   </B>'
        for tunnel in ACTIVE_TUNNELS:
            response += '</BR>***Tunnel from: ' + tunnel.bss + ' to: ' + tunnel.apn.name + '***</BR>'
            for node in tunnel.path_out:
                response += str(node.dpid) + ' via port: ' + str(node.port_out) +', '
            response += '</BR>***Tunnel from: ' + tunnel.apn.name + ' to: ' + tunnel.bss + '***</BR>'
            for node in tunnel.path_in:
                response += str(node.dpid) + ' via port: ' + str(node.port_out) +', '


        response +=      '</BR><B>Inactive tunnels: </B>'
        for tunnel in INACTIVE_TUNNELS:
            response += '</BR>***Tunnel from: ' + tunnel.bss + ' to: ' + tunnel.apn.name + '***</BR>'
            for node in tunnel.path_out:
                response += str(node.dpid) + ' via port: ' + str(node.port_out) +', '
            response += '</BR>***Tunnel from: ' + tunnel.apn.name + ' to: ' + tunnel.bss + '***</BR>'
            for node in tunnel.path_in:
                response += str(node.dpid) + ' via port: ' + str(node.port_out) +','



        response +=      '</BR><B>Static topology graph nodes:  </B>' + str(topo.StaticGraph.nodes())
        response +=      '</BR><B>Dynamic topology graph nodes: </B>' + str(topo.DynamicGraph.nodes())

        #FIXME: Temporary hack (0th index), since we have only one ePCU/PCU-ng at the time being == one entry point for GPRS traffic, and also one exit point (Internet)
        try:
            #already implemented in topology class(get_tunnel function), but I am not particularly happy with it ==> standard networkX call used, works as a charm
            path_out = nx.shortest_path(topo.DynamicGraph, BSS_EDGE_FORWARDER[0], INET_EDGE_FORWARDER[0])
            path_in  = nx.shortest_path(topo.DynamicGraph, INET_EDGE_FORWARDER[0], BSS_EDGE_FORWARDER[0])
            LOG.debug('STATUS DUMP: Path between GPRS edge and Internet found: ' + str(path_out))
            LOG.debug('STATUS DUMP: Path between Internet edge na GPRS edge found: ' + str(path_in))
        except nx.NetworkXNoPath:
            LOG.warning("STATUS DUMP: Warning: Couldn't find path, network might not be converged yet. Retrying when next forwarder joins network.")
            path_out = []
            path_in  = []

        if BSS_EDGE_FORWARDER and INET_EDGE_FORWARDER \
           and  topo.StaticGraph.number_of_nodes() and topo.DynamicGraph.number_of_nodes() \
           and (BSS_EDGE_FORWARDER[0] in topo.StaticGraph) and (BSS_EDGE_FORWARDER[0] in topo.DynamicGraph) \
           and (INET_EDGE_FORWARDER[0] in topo.StaticGraph) and (INET_EDGE_FORWARDER[0] in topo.DynamicGraph) \
           and len(path_out) and len(path_in):


            response += '</BR><B>Path to the Internet:  </B>' + str(path_out)
            response += '</BR><B>Path to the GPRS edge: </B>' + str(path_in)
            response += '<H1 style="color:green"> TOPOLOGY HEALTHY! </H1>'
        else:
            response += '<H1 style="color:red"> TOPOLOGT NOT HEALTHY </H1>'


        if TUNNELS:
            response += '<H2 style="color:green"> USER-PLANE TUNNELS ARE PRESENT </H2>'
        else:
            response += '<H2 style="color:orange"> USER-PLANE TUNNELS NOT PRESENT </H2>'


        LOG.debug('STATUS DUMP: Dumping Topology state at /test/info URL!')
        return (response)

    def dump_topology (self, req):
        LOG.debug('TOPO DUMP: Dumping topology to JSON at /topology/dump ')
        return (Response(content_type='application/json', body=topo.dump(), headerlist=[('Access-Control-Allow-Origin', '*')]))

    def set_measurement_interval(self, req, interval):
        LOG.debug('MEASURE MNGR: Setting measurement interval to: ' + str(interval))
        global MEASUREMENT_INTERVAL
        MEASUREMENT_INTERVAL = int(interval)
        return Response(status=200, content_type='text',body='MEASURE MNGR: MEASUREMENT_INTERVAL set to: ' + str(MEASUREMENT_INTERVAL))

    def set_class_one(self, req, dscps):
        global CLASS_ONE
        CLASS_ONE = map(int, dscps.split())
        LOG.debug("TE MNGR: CLASS_ONE set to: " + str(CLASS_ONE))
        return Response(status=200, content_type='text',body="TE MNGR: CLASS_ONE set to: " + str(CLASS_ONE))

    def set_class_two(self, req, dscps):
        global CLASS_TWO
        CLASS_TWO = map(int, dscps.split())
        LOG.debug("TE MNGR: CLASS_TWO set to: " + str(CLASS_TWO))
        return Response(status=200, content_type='text', body="TE MNGR: CLASS_TWO set to: " + str(CLASS_TWO))

    def set_latencies(self, req, thresholds):
        global CLASS_ONE_LAT
        global CLASS_ONE_LAT_VAR
        global CLASS_TWO_LAT
        thresholds = map(float, thresholds.split())
        CLASS_ONE_LAT = thresholds[0]
        CLASS_ONE_LAT_VAR = thresholds[1]
        CLASS_TWO_LAT = thresholds[2]
        LOG.debug("TE MNGR: CLASS_TWO set to: " + str(CLASS_TWO))
        return Response(status=200,body="TE MNGR: <br>CLASS_ONE_LAT set to: " + str(CLASS_ONE_LAT)
                                        + "<br> CLASS_ONE_LAT_VAR set to: " + str(CLASS_ONE_LAT_VAR)
                                        + "<br> CLASS_TWO_LAT set to: " + str(CLASS_TWO_LAT))


    def mod_pdp (self, req, cmd):
        #parsing GET parameters out of REST call
        body = urlparse.parse_qs(cmd)

        ##TODO:Change vGSN to make REST call in format where 'cmd' is paired with value, for now we assume cmd=add
        #parse_qs method returns results with garbage around, this ugly hack cuts it away [3:-2]
        start = str(body.get('rai'))[3:-2]
        end = str(body.get('apn'))[3:-2]
        imsi = str(body.get('imsi'))[3:-2]
        bvci = int(str(body.get('bvci'))[3:-2])
        tlli = int(str(body.get('tlli'))[3:-2], 16)
        drx_param = int(str(body.get('drx_param'))[3:-2], 16)
        sapi = int(str(body.get('sapi'))[3:-2])
        nsapi = int(str(body.get('nsapi'))[3:-2])


        tid_out=None
        tid_in=None
        #XXX:How about a HTTP response to vGSN if required tunnel doesnt exist?
        ## We find tunnel that matches criteria from Activate PDP context request
        for act_tunnel in ACTIVE_TUNNELS:
            if start == act_tunnel.bss and end == act_tunnel.apn.name:
                tid_out = act_tunnel.tid_out
                tid_in = act_tunnel.tid_in
                path_in =  act_tunnel.path_in
                path_out = act_tunnel.path_out

        #XXX:review, maybe larger ip pool, for now it's enough
        #TODO:in case on CNT deactivation, return IP to pool
        ## IP address is picked, in case there is no left, method ends and returns Internal Error HTTP response to caller
        if len(IP_POOL) == 0:
            LOG.error('ERROR: We are out of IP addresses')
            return Response(status=500, content_type='text',body='Out of IPs')

        client_ip=IP_POOL.pop()

        #TODO: Handling of 'cmd' value
        ACTIVE_CONTEXTS.append( PDPContext(bvci, tlli, sapi, nsapi, tid_out, tid_in, client_ip, imsi, drx_param) )

        ###WAY OUT
        ##First node on the way OUT removes GPRS headers, sets eth addr. to appropriate tunnel ID
        ##and sends packet to table MAC_TUNNEL_TABLE
        ##In_port of packet on first node on its way OUT is equal to the port_out of last node on the way IN, therfore in_port=path_in[-1].port_out
        dp = self.dpset.get(path_out[0].dpid)
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        match = parser.OFPMatch( in_port=path_in[-1].port_out,
                                 ns_type=0,
                                 ns_bvci=bvci,
                                 bssgp_tlli=tlli,
                                 llc_sapi=sapi,
                                 sndcp_nsapi=nsapi)

        actions = [GPRSActionPopGPRSNS(), GPRSActionPopUDPIP(),
                   parser.OFPActionSetField(eth_src=tid_in),parser.OFPActionSetField(eth_dst=tid_out)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionGotoTable(MAC_TUNNEL_TABLE)]
        req = parser.OFPFlowMod(datapath=dp, priority=100, match=match, instructions=inst, table_id = OF_GPRS_TABLE)
        dp.send_msg(req)


        ###WAY IN
        ##On the way IN we need to match packet on both first and last forwarder
        ##First forwarder matches Clients IP to determine appropriate tunnel
        ##for first in_port match aplies same rule as on the way out: in_port=path_out[-1].port_out
        dp = self.dpset.get(path_in[0].dpid)
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        match = parser.OFPMatch(in_port=path_out[-1].port_out,
                                eth_type=0x0800,
                                ipv4_dst=client_ip)
        actions = [ parser.OFPActionSetField(eth_dst=tid_in), parser.OFPActionSetField(eth_src=tid_out) ]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionGotoTable(MAC_TUNNEL_TABLE)]
        req = parser.OFPFlowMod(datapath=dp, priority=300, match=match, instructions=inst, table_id = 0)
        dp.send_msg(req)

        dp = self.dpset.get(path_in[-1].dpid)
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        ##XXX:Setfield eth_dst is ahrdcoded to work with our BTS!
        ##Last forwarder machtes Clients IP to push appropriate GPRS headers and determine port_out
        match = parser.OFPMatch(eth_type=0x0800,
                                ipv4_dst=client_ip)
        actions=[ GPRSActionPushGPRSNS(bvci, tlli, sapi, nsapi, drx_param, imsi),
                  GPRSActionPushUDPIP(sa=VGSN_IP, da=BSS_IP, sp=VGSN_PORT, dp=BSS_PORT),
                  parser.OFPActionSetField(eth_dst='00:d0:cc:08:02:ba'),
                  parser.OFPActionOutput(path_in[-1].port_out)]
        inst=[ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]

        req = parser.OFPFlowMod(datapath=dp, priority=100, match=match, instructions=inst, table_id = OF_GPRS_TABLE_IN)
        dp.send_msg(req)

        return (Response(content_type='application/json', body='{"address":"'+client_ip+'","dns1":"8.8.8.8","dns2":"8.8.8.8"}'))

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
    def __init__(self, bvci, tlli, sapi, nsapi, drx_param, imsi):
        super(GPRSActionPushGPRSNS,self).__init__(0x0001)
        self.len = 32
        self.bvci = bvci
        self.tlli = tlli
        self.sapi = sapi
        self.nsapi = nsapi
        self.drx_param = drx_param
        self.imsi = imsi

    def serialize(self, buf, offset):
        """ Serialize PushGPRSNS action into buffer. """
        super(GPRSActionPushGPRSNS,self).serialize(buf, offset)

        imsi_bytes = imsi_to_bytes(self.imsi)

        LOG.debug("push_gprsns.serialize self="+pprint.pformat(self))
        ofproto_parser.msg_pack_into("!HxxIHBBHBBBBBBBBBx", buf, offset+8, 
                self.subtype, self.tlli, self.bvci, self.sapi, self.nsapi, self.drx_param, 
                len(imsi_bytes), *imsi_bytes)

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
