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

import urllib2
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

###Global variable initialization

##logger
##Usage: LOG.debug() / LOG.warning() / LOG.error()
LOG = logging.getLogger('ryu.app.roaming_magic.py')

##Static definition of of ports for vGSN and BSS
##TODO: Remove static definition(Either self-discovery or Yang)
BSS_PHY_PORT = 1
VGSN_PHY_PORT = 2
INET_PHY_PORT = None
ROAMING_PHY_PORT = None

##IP adresses used when controller generates packets
DISCOVERY_IP_SRC='10.1.1.252'
DISCOVERY_IP_DST='10.1.1.253'
##Due to nature of ARP protocol, DISCOVERY_ARP_IP must be in same subnet as host you want to discover
DISCOVERY_ARP_IP='172.20.255.99'
#DISCOVERY_ARP_IP='172.21.255.99'
SNDCP_FRAG_WARNING_SRC_IP='224.42.42.3'

##Experimenter ID (self-assigned)
GPRS_SDN_EXPERIMENTER = int("0x42", 16)

##Number of OF table that contains GPRS-related flow rules on the way OUT
OF_GPRS_TABLE = 2

##Number of OF table that contains GPRS-related flow rules on th way IN
OF_GPRS_TABLE_IN = 4

##Number of OF table that contains MAC_TUNNEL-related flow rules
MAC_TUNNEL_TABLE = 3

##Hardcode IP adresses of our GPRS nodes
BSS_IP="192.168.25.1"
BSS_PORT=22000
BSS_MAC = "de:aa:05:32:b9:01"
#open('/sys/class/net/bss1/address').read()
LOG.debug('BSS MAC ADDRESS IS: %s' % BSS_MAC)

VGSN_IP="192.168.27.2"
#VGSN_MAC="16:7d:bd:e4:6c:5c"
VGSN_MAC = open('/sys/class/net/vgsn1/address').read()
LOG.debug('vGSN MAC ADDRESS IS: %s' % VGSN_MAC)

#VGSN_IP="192.168.28.2"
VGSN_PORT=23000

##Forwarders assigned to special groups
##XXX:Review usefulness
BSS_EDGE_FORWARDER=[0xa]
INET_EDGE_FORWARDER=[0xc]
ROAMING_EDGE_FORWARDER=[0xb]

##Generation of IP adresses  asigned to devices on PDP CNT actiavation
##XXX:Modify pool if needed
IP_POOL=[]
for i in range(100,199):
    IP_POOL.append('172.20.85.'+str(i))
#    IP_POOL.append('172.21.85.'+str(i))

##List of APNs in network
APN_POOL=[]

##List containing IP and MAC addresses to contact roaming partners' APNs
ROAMING_APN_POOL=[]

##List of BSSs in network
#XXX:for now it's static
#BSS_POOL=['901-70-1-0']
#BSS_POOL=['231-01-1-0']
BSS_POOL = []

##List of active PDP CNTs
ACTIVE_CONTEXTS = []

##List of active tunnels
ACTIVE_TUNNELS=[]

##List of inactive tunnels (those that could not be created due to lack of path between end nodes)
INACTIVE_TUNNELS=[]

##List of used Tunnel identifiers
TID_POOL = []

##Local MCC + MNC identifying our network
MCC_MNC = '23101'
#MCC_MNC = '90170'

##List of roaming partners (controllers)
ROAMING_PARTNERS = {}
ROAMING_PARTNERS['90170'] = 'http://192.168.28.1:8080/gprs/'
#ROAMING_PARTNERS['23101'] = 'http://192.168.27.1:8080/gprs/'

##Returns true, if roaming partner exists
def roaming_partner_exists(imsi):
	
    if ROAMING_PARTNERS.has_key(imsi[:5]):
	return True
    return False

##Returns IMSI, if roaming subscriber can attach to our network
def get_roaming_data(id_type, id_value, action, url):
    
    #find a roaming partner for this IMSI/P-TMSI
    if action == 'att':

	#XXX add new rai	
	if id_type == 'imsi':
		url += 'roam_mm/cmd=atti&imsi=' + id_value

	elif id_type == 'p-tmsi':	
		url += 'roam_mm/cmd=attp&p-tmsi=' + id_value
    
    elif action == 'det':	
		url += 'roam_mm/cmd=det&imsi=' + id_value

    LOG.debug('GMM get_roaming_data URL: ' + url)	
    #ask the remote controller for approval 
    result = urllib2.urlopen(url)
    if result.getcode() != 200:
	return None

    data = json.loads(result.read())
    LOG.debug(str(data))
    if data['result'] == 'success':
	return data['imsi']
    return None

#Returns true, if roaming partner succesfully builds/destroys tunnels (and rules) for his MS    
def get_roaming_tunnel(action, imsi, apn):
    if roaming_partner_exists(imsi[:5]):
	#activate PDP context
	if action == 'add':
	    url = ROAMING_PARTNERS[imsi[:5]]
	    url += 'roam_sm/cmd=add&imsi=' + imsi + '&apn=' + apn.name 
	    
	    LOG.debug('SM get_roaming_tunnel URL: ' + url)    
            #ask the roaming partner's controller to create rules
	    result = urllib2.urlopen(url)
		
	    data = json.loads(result.read())
	    LOG.debug(str(data))
	    if result.getcode() == 200:
	        return data['address']
	    return None
	
	#deactivate PDP context
	elif action == 'del':
	    url = ROAMING_PARTNERS[imsi[:5]]
	    url += 'roam_sm/cmd=del&imsi=' + imsi + '&apn=' + apn.name + '&address=' + ip_addr
		
	    LOG.debug('SM get_roaming_tunnel URL: ' + url)
	    #ask the roaming partner's controller to delete rules
	    result = urllib2.urlopen(url)
	    
	    data = json.loads(result.read())
	    LOG.debig(str(data))
	    if result.getcode() == 200:
		return True
	    return None    
    #bad URL or failed command 
    return None
 
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

        _bss_ -- BSS endpoint idetifier in topology (must be of bss class)
        _apn_ -- APN endpoint (must be of apn class)
        tid_out -- Tunnel identifier in outgoing direction (MAC addr. format)
        tid_in -- Tunnel identifier in incoming dirrection (MAC addr. format)
        path_out -- list of links for outgoing direction
        path_in -- list of links for incoming direction
    """
    def __init__(self, _bss_, _apn_, _tid_out, _tid_in, path_out=None, path_in=None):
      self.bss = _bss_
      self.apn = _apn_
      self.tid_out = _tid_out
      self.tid_in = _tid_in
      self.path_in = path_in
      self.path_out = path_out


class apn:
    """
    Access point defined by its name, IP and mac addr. APN's only mandatory arg. is name
    IP and mac addr. are resolved with DNS/ARP provided there is DNS entry available

    Keyword arguments:
        name -- Acces Point Name (string)
        ip_addr -- IP address of APN
        eth_addr -- MAC address of APN
    """
    def __init__(self, name, ip_addr=None, eth_addr=None):
        self.name = name
        self.ip_addr = ip_addr
        self.eth_addr = eth_addr

class bss:
    """
    BSS defined by its name, which equals to its MCC-MNC-LAC-RAC, ITS IP and MAC addresses. BSS's  mandatory arg. is name and IP address.

    Keyword arguments:
        name -- MCC-MNC-LAC-RAC (string)
        ip_addr -- IP address of APN
        eth_addr -- MAC address of APN
    """
    def __init__(self, name, ip_addr, eth_addr=None):
	self.name = name
	self.ip_addr = ip_addr
	self.eth_addr = eth_addr
    
##XXX:maybe should be created from config file (Yang?)
APN_POOL.append(apn('internet'))
#ip address of the next VM
#mac address of the next VM

BSS_POOL.append(bss('231-1-10-0', BSS_IP))
#BSS_POOL.append(bss('901-70-1-0', BSS_IP))
ROAMING_APN_POOL.append(apn('90170', '192.168.28.1', '08:00:27:eb:88:a7'))
#ROAMING_APN_POOL.append(apn('23101', '192.168.27.1', '08:00:27:eb:88:a7'))

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
        #self.add_link('901-70-1-0',0xa,1)
        #self.add_link(0xa,'901-70-1-0',1)
	self.add_link('231-1-10-0',0xa,1)
	self.add_link(0xa,'231-1-10-0',1)

	#Roaming link to other PLMN (91070) <-> 0xb
	self.add_link(0xc, '90170', 4)
 	self.add_link('90170', 0xc, 0)	
	#self.add_link(0xc,'23101',4)
	#self.add_link('23101',0xc,0)

	#vGSN node <-> 0xa
        #XXX:self.add_link(1,0xa,1)
        #XXX:self.add_link(0xa,1,2)
        #internet <-> 0xc
        #self.add_link('internet',0xc,1)
        #self.add_link(0xc,'internet',3)
        self.reload_topology()

    def dump(self):
	data = json_graph.node_link_data(self.DynamicGraph)
	return json.dumps(data)

    def add_forwarder(self, fwID):
        self.StaticGraph.add_node(fwID)

    def del_forwarder(self, fwID):
        self.DynamicGraph.remove_node(fwID)

    def add_link(self, fwID1, fwID2, ifnumm):
        self.StaticGraph.add_edge(fwID1, fwID2, interf=ifnumm)

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

    def get_tunnel(self, fwID1, fwID2):
        hops = nx.shortest_path(self.DynamicGraph, fwID1, fwID2)
        path = []
        tunnelID=get_tid()
        for k in hops[1:-1]:
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
    LOG.debug('Eth dst: ' +eth_dst+ ' eth_src:  eth_target: ' +eth_target)


    ofp = dp.ofproto
    parser = dp.ofproto_parser
    pkt = packet.Packet()

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
    if eth_target == VGSN_MAC:
	eth = ethernet.ethernet(eth_dst, eth_target, ether.ETH_TYPE_ARP)
    	arp_req = arp.arp_ip(arp_code, eth_target, ip_sender, eth_target, ip_target)

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

    ##TODO: Rework payload and codes to properly work with Fragmentation needed
    pkt.add_protocol(icmp.icmp(type_=icmp_type,
                               code=icmp_code,
                               csum=0,
                               data=icmp.echo(1,1,"{'dpid' : "+str(dp.id)+",'port_out' : "+str(port_out)+"}")))
    pkt.serialize()
    data=pkt.data
    actions=[parser.OFPActionOutput(port_out,0)]
    out=parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER, actions=actions, data=data)
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


class Subscriber():
    """
    Class used to stored subscriber info.    
    
    Keyword arguments:

    imsi -- International Mobile Subscriber Identity
    ptmsi -- Packet Temporary Mobile Subscriber Identity - optional
    location -- Routing Area Identity - optional
    roaming_allowed -- flag indicating if roaming is permitted for this subscriber - optional 
    """
    def __init__(self, imsi, ptmsi, name, location=None, roaming_allowed=None):
	self.imsi = imsi
	self.ptmsi = ptmsi
	self.name = name
	self.location = location
	self.roaming_allowed = roaming_allowed

##Database of all local subscribers (HLR)
##and active (attached)/inactive(formerly attached) subscribers
class HLR():
	
    def __init__(self):
    	#dictionary containing subscriber info, IMSI serves as the key 
	#value is an object of Subscriber class
	self.subscribers = {}

	#dictionary of active MM contexts, IMSI serves as the key
	#value is the P-TMSI of the MS 
	self.active_subscribers = {}

	#dictionary containing inactive (detached) MM contexts
	#P-TMSI is used as the key
	#IMSI is used as the value
	self.inactive_subscribers = {} 
   	
	#list of local subscribers attached to a different PLMN but accessing Internet through their home "GGSN"
	self.active_roaming_subscribers = []

 
    #returns True if MS exists in local HLR
    def find_ms_by_imsi(self, imsi):
	if self.subscribers.has_key(imsi):
	    return True
	return False
  
    #returns True if MM ctx exists 
    def find_mm_ctx_by_imsi(self, imsi):
        if self.active_subscribers.has_key(imsi):
	    return True
	return False 
    	
    #return IMSI if active/inactive MM context exists
    def find_mm_ctx_by_ptmsi(self, ptmsi):
	#find active MM ctx by P-TMSI
	for imsi,ptmsi_old in self.active_subscribers.iteritems():
	    if ptmsi == ptmsi_old:
		return imsi
	#find inactive MM ctx by P-TMSI
	for imsi,ptmsi_old in self.inactive_subscribers.iteritems():
	    if ptmsi == ptmsi_old:
		return imsi
 	#no MM ctx found
	return None

    #creates MM contexts, returns P-TMSI if successful
    def create_mm_ctx(self, imsi):
	
	#delete any existing PDP contexts for this MS
	#XXX remove forwarder rules
	for ctx in ACTIVE_CONTEXTS:
	    if ctx.imsi == imsi:
		ACTIVE_CONTEXTS.remove(ctx)

	#check if an inactive MM ctx exists, if yes, make it active and generate new P-TMSI
	if self.inactive_subscribers.has_key(imsi):
	    self.inactive_subscribers.pop(imsi, None)
	    self.active_subscribers[imsi] = self.generate_ptmsi()
	    return self.active_subscribers[imsi]
	
	#check if an active MM ctx exists and if yes, update P-TMSI
	elif self.active_subscribers.has_key(imsi):
	    self.active_subscribers[imsi] = self.generate_ptmsi()
	    return self.active_subscribers[imsi]

	#create MM ctx, generate new P-TMSI	
	else:
	    self.active_subscribers[imsi] = self.generate_ptmsi()
	    return self.active_subscribers[imsi]
    
    #returns random generated P-TMSI
    def generate_ptmsi(self):
	#generate random 4 byte P-TMSI
	new_ptmsi =  hex(random.randint(0,4294967294) | 0xC0000000)
	#check if it is unique
	if not self.find_mm_ctx_by_ptmsi(new_ptmsi):
	    return new_ptmsi
	#if not, generate again
	return self.generate_ptmsi()

    #deletes MM ctx, returns True if sucessful
    def delete_mm_ctx(self, p_tmsi):
 	#find MM ctx with P-TMSI in active contexts and make it inactive
        #XXX deactivate PDP ctxts
	for imsi,ptmsi_old in self.active_subscribers.iteritems():
            if p_tmsi == ptmsi_old:
	        self.active_subscribers.pop(imsi, None)
		self.inactive_subscribers[imsi] = p_tmsi
	    	return True
	return False

##HLR initialization
hlr = HLR()
hlr.subscribers['231014450469959'] = Subscriber('231014450469959', None, 'Tibor', None, None)
hlr.subscribers['231014453285311'] = Subscriber('231014453285311', None, 'Iva', None, None) 
hlr.subscribers['231011234567890'] = Subscriber('231011234567890', None, 'tester', None, None)
#hlr.subscribers['901704450469959'] = Subscriber('901704450469959', None, 'Tibor', None, None)
#hlr.subscribers['901704453285311'] = Subscriber('901704453285311', None, 'Iva', None, None) 
#hlr.subscribers['901701234567890'] = Subscriber('901701234567890', None, 'tester', None, None)

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


        uri = path + '/sm/{cmd}'
        mapper.connect('stats',uri,
                       controller=RestCall, action='mod_sm',
                       conditions=dict(method=['GET']))

        uri = '/topology/dump'
        mapper.connect('stats',uri,
                       controller=RestCall, action='dump_topology',
                       conditions=dict(method=['GET', 'HEAD']))
	
	uri = path + '/gmm/{cmd}'
        mapper.connect('stats',uri,
                       controller=RestCall, action='mod_gmm',
                       conditions=dict(method=['GET']))
	
	uri = path + '/roam_mm/{cmd}'
	mapper.connect('stats',uri,
                       controller=RestCall, action='mod_roam_mm',
                       conditions=dict(method=['GET']))

	uri = path + '/roam_sm/{cmd}'
	mapper.connect('stats',uri,
		       cpontroller=RestCall, action='mod_roam_sm',
                       conditions=dict(method=['GET']))	

        #Testing
        uri =  '/test/info'
        mapper.connect('stats', uri,
                        controller=RestCall, action='test_info',
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
	
	#XXX: do the same for roaming partners
	#define them statically but finds IPs through DNS
   
    def on_edge_inet_dp_join(self, dp, port):
        """ Add special rules for forwader on edge (APN-side) of network

            Keyword arguments:
                dp -- datapath
                port -- ID of port with APN on the other side
        """

        ofp = dp.ofproto
        parser = dp.ofproto_parser

        ##All ARP requests that come from APN are forwarded to Controller which then handle them
        ##TODO: Pass also APN object so we can put it to debug log :)
        LOG.debug('TOPO MNGR: Redirecting all ARP req from APN to controller by OFrule on forwarder: ' + str(dp.id))
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
        self.add_flow(dp, 100, match, actions)
         
        ##Controller uses ARP to resolve mac_addresses of APNs
        ##All arp replies with target IP of DISCOVERY_ARP_IP are redirected to controller
        LOG.debug('TOPO MNGR: Installing ARP APN discovery flows on forwarder: ' + str(dp.id))
        match = parser.OFPMatch(eth_type=0x0806, arp_op=2, arp_tpa=DISCOVERY_ARP_IP)
        actions = [ parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]
        self.add_flow(dp, 100, match, actions)

 

        ##Following rules are applied only on forwarders bellonging to BSS_EDGE_FORWARDER group
        ##Rules are applied based on priority of match (highest priority first)
        if dp.id in BSS_EDGE_FORWARDER:
            LOG.debug('TOPO MNGR: Redirecting all ARP req from BSS simulator to controller by OFrule on forwarder: ' + str(dp.id))
            match = parser.OFPMatch(in_port=BSS_PHY_PORT, eth_type=0x0806, arp_op=1)
            actions = [ parser.OFPActionOutput(ofp.OFPP_CONTROLLER) ]
            inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
            req = parser.OFPFlowMod(datapath=dp, priority=10, match=match, instructions=inst)
            dp.send_msg(req)
            
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
            ##TODO: BSS <-> vGSN separate tunnel for communication!
            ##TODO: deletion, modification od  PDP CNT

            ## if packet is not first segment  of user data packet (IS part of sndcp fragmented packet) it's DROPPED
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
    
            ##if it's SNDCP packet that still wasnt matched (rules with higher priority are inserted on PDP CNT activation)
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


    def stats_reply_handler(self, ev):
        """
        This method iss responsible for generation of HTTP replies to the REST calls
        """
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

    @set_ev_cls(ofp_event.EventOFPPacketIn)
    def _packet_in(self, ev):
        """
        This method handles are packets that arrive directly to Controller
        """

        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = ev.msg.match

        ##SNDCP packet with multiple fragments received - print warning, send ICMP fragmentation needed
        ##TODO: Not WOrking correctly
        if (match['eth_type'] == 0x0800 and match['ip_proto'] == inet.IPPROTO_UDP 
            and match['udp_dst'] == VGSN_PORT and match['sndcp_first_segment'] == 1 
            and match['sndcp_more_segments'] == 1):
            _icmp_send(dp,match['in_port'],match['ipv4_dst'],match['ipv4_src'],match['eth_dst'],match['eth_src'],icmp_type=3,icmp_code=4)
            LOG.warning('WARNING: Device with IP: '+match['ipv4_src']+' sent fragmented sndcp packet')
            return

        ##ARP request received - send 'I'm here' response
        if match['eth_type'] == 0x0806 and match['arp_op'] == 1:
            LOG.debug("PKT HND: ARP REQ HND: ARP request recieved")
            if match['arp_spa'] == match['arp_tpa'] and match['eth_dst'] == 'ff:ff:ff:ff:ff:ff':
                LOG.debug('PKT HND: ARP REQ HND:  This is a gratious ARP, we are not going to respond')
            else:
                prefix=match['arp_tpa'][:7]
                if prefix == "169.254": 
                    LOG.debug('PKT HND: ARP REQ HND: This is self assigned IP limited to LAN, not going to respond')
                else:
                    LOG.debug('PKT HND: ARP REQ HND: ARP request is a valid one, responding')
		    if match['arp_tpa'] == VGSN_IP:
			_arp_send(dp=dp, port_out=match['in_port'], arp_code=2, eth_dst=match['eth_src'], eth_target=VGSN_MAC,
                      ip_target=match['arp_spa'], ip_sender=match['arp_tpa'])
                	LOG.debug('PKT HND: ARP REQ HND: Reply to '+match['arp_spa'] +': Host '+match['arp_tpa']+' has this MAC '+VGSN_MAC )
                    
		    else:
			_arp_send(dp=dp, port_out=match['in_port'], arp_code=2, eth_dst=match['eth_src'], eth_target=match['arp_sha'],
                      ip_target=match['arp_spa'], ip_sender=match['arp_tpa'])
                LOG.debug('PKT HND: ARP REQ HND: Reply to '+match['arp_spa'] +': Host '+match['arp_tpa']+' is at forwarder '+str(dp.id) )
            return

        ##ARP response with target_ip==DISCOVERY_ARP_IP recieved - we found APN
        if match['eth_type'] == 0x0806 and match['arp_op'] == 2 and match['arp_tpa'] == DISCOVERY_ARP_IP:
            LOG.debug('TOPO MNGR: ARP response with target APN discovery IP received at controller, processing for APN extraction')
            pkt = packet.Packet(array.array('B', ev.msg.data))
            arp_pkt=pkt.get_protocol(arp.arp)
            apn_ip = arp_pkt.src_ip
            apn_mac= arp_pkt.src_mac
            port = match['in_port']
            
            ##Search for apn in APN_POOL to add mac addr. and update topology
            for apn in APN_POOL:
                if apn.ip_addr == apn_ip:
		    apn.eth_addr = apn_mac
                    topo.add_link(dp.id,str(apn.name),port)
                    topo.add_link(str(apn.name),dp.id,0)
                    topo.reload_topology()
                    LOG.debug('TOPO MNGR: APN '+str(apn.name)+' found at forwarder: '+str(dp.id)+', port: '+str(port) + ' by ARP search')
                    
                    ##Add special rules to edge forwarder
                    self.on_edge_inet_dp_join(dp, port)  
                    ##Create MAC-tunnels between APN and all BSSs
                    for bss in BSS_POOL:
                        self.add_tunnel(bss,apn)
			for roaming_forwarder in ROAMING_APN_POOL:
			    self.add_tunnel(bss, roaming_forwarder)
			    self.add_tunnel(roaming_forwarder, apn)
		    break	 
	    return

        ##ICMP echo with dst_ip==DISCOVERY_IP_DST received - new link between forwarders is up
        if match['eth_type'] == 0x0800 and match['ipv4_dst'] == DISCOVERY_IP_DST and match['ip_proto'] == 1:
            LOG.debug('TOPO MNGR: ICMP echo recieved at controller, processing for link extraction')
            pkt = packet.Packet(array.array('B', ev.msg.data))

            ##Discovery pings carry information about sending datapath in payload of icmp packet
            ##these information are in Dictionary format, we parse the out with _icmp_parse_payload() method
            body = _icmp_parse_payload(pkt) 
            neighbourDPID=body['dpid']
            neighbourPort=body['port_out']
            
            ##and add them to topology.
            topo.add_link(ev.msg.datapath.id, neighbourDPID, ev.msg.match['in_port'])
            topo.add_link(neighbourDPID, ev.msg.datapath.id, neighbourPort )
            topo.reload_topology()
            LOG.debug('TOPO MNGR: Topology changed: New link between '+str(ev.msg.datapath.id)+' and '+str(neighbourDPID)+' was discovered.')

            ##retry to create inactive tunnels/find better paths for already active tunnels
            self.retry_tunnels()
        return

    @set_ev_cls(dpset.EventDP, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def forwarder_state_changed(self, ev):
        """
        This method handles change of forwarders state

        ev.enter is True   -- New forwarder is connected
        ev.enter is False  -- Forwarder got disconnected  
        """

        dp = ev.dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser
            
        if ev.enter is True:
            self.on_inner_dp_join(dp)
	    ##For evry new forwarder we send out discovery ICMP packets out of every port except OFPP_CONTROLLER
            LOG.debug('TOPO MNGR: Forwarder: ' + str(dp.id) + ' saying hello to Unifycore Controller, Unifycore warmly welcomes you!')
            for port in dp.ports:
                if port != (ofp.OFPP_CONTROLLER):
                    LOG.debug('TOPO MNGR: Controller is sending topology discovery ICMPs to forwarder: ' + str(dp.id) + ', port: ' + str(port))
                    _icmp_send(dp,port,DISCOVERY_IP_SRC, DISCOVERY_IP_DST)
                    for apn in APN_POOL:
                        if apn.ip_addr != None:
                            LOG.debug('TOPO MNGR: Forwarder: '+str(dp.id)+', port: '+ str(port)   + ' is looking for APN: ' + str(apn.name) +' at IP: '+str(apn.ip_addr)+' with ARP search')
                            _arp_send(dp=dp, port_out=port, arp_code=1, ip_target=apn.ip_addr, ip_sender=DISCOVERY_ARP_IP)

        if ev.enter is False:
	    ##TODO: We need to scan if any tunnels were affected, and if so, if any PDP Contexts were affected
            ##JUST REMOVING NODE FROM TOPOLOGY ISNT ENOUGH!
            LOG.debug('TOPO MNGR: Forwarder: ' + str(dp.id) + ' is leaving topology. It was a pleasure for us!')
            topo.del_forwarder(dp.id)

    def retry_tunnels(self):
        """ 
             This is very similar to add_tunnel method...I'm too tired to make and call
             modified version of add_tunnel... 
        """
        ##Search inactive tunels to see if any path can be resolved now, if yes...do the same thing as add_tunnel()
        for inact_tunnel in INACTIVE_TUNNELS:
            try:
                self.path_out = topo.get_tunnel(inact_tunnel.bss.name, inact_tunnel.apn.name)
                self.path_in  = topo.get_tunnel(inact_tunnel.apn.name, inact_tunnel.bss.name)
                
            except nx.NetworkXNoPath:
                LOG.warning("Warning: Couldn't find path, network might not be converged yet. Retrying when next forwarder joins network...again...")
                return
            
            INACTIVE_TUNNELS.remove(inact_tunnel)

            ##Set forwarding rules for all but last forwarder on the way OUT 
            ##On first forwarder on the way OUT these rules are placed into table MAC_TUNNEL_TABLE while on 'dumb' forwarders it goes to 0
            dp = dpset.get(self.path_out[0].dpid)
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_dst=inact_tunnel.tid_out)
            actions = [parser.OFPActionOutput(self.path_out[0].port_out)]
            self.add_flow(dp, 300, match, actions, MAC_TUNNEL_TABLE)

            ##Rules for all 'dumb' forwardes on the way OUT
            for node in self.path_out[1:-1]:
                dp = dpset.get(node.dpid)
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_dst=inact_tunnel.tid_out)
                actions = [parser.OFPActionOutput(node.port_out)]
                self.add_flow(dp, 300, match, actions, 0)

            ##Last forwarder on the way OUT needs to set eth_dst to eth_addr of APN otherwise it wont be processed
            dp = dpset.get(self.path_out[-1].dpid)
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_dst=inact_tunnel.tid_out)
            actions = [ parser.OFPActionSetField(eth_dst=inact_tunnel.apn.eth_addr), parser.OFPActionOutput(self.path_out[-1].port_out)]
            self.add_flow(dp, 300, match, actions, 0)

            ##Here comes tunnel for the way IN
            ##On first forwarder on the way IN these rules are placed into table MAC_TUNNEL_TABLE while on 'dumb' forwarders it goes to 0
            dp = dpset.get(self.path_in[0].dpid)
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_dst=inact_tunnel.tid_in)
            actions = [parser.OFPActionOutput(self.path_in[0].port_out)]
            self.add_flow(dp, 300, match, actions, MAC_TUNNEL_TABLE)

            ##Rules for all 'dumb' forwardes on the way IN
            for node in self.path_in[1:-1]:
                dp = dpset.get(node.dpid)
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_dst=inact_tunnel.tid_in)
                actions = [parser.OFPActionOutput(node.port_out)]
                self.add_flow(dp, 300, match, actions, 0)

            ##Last forwarder on the way IN sends packet to table OF_GPRS_TABLE_IN where it's matched based on active PDP CNTs
            dp = dpset.get(self.path_in[-1].dpid)
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_dst=inact_tunnel.tid_in)
            inst = [ parser.OFPInstructionGotoTable(OF_GPRS_TABLE_IN) ]
            req = parser.OFPFlowMod(datapath=dp, priority=500, match=match, instructions=inst, table_id=0)
            dp.send_msg(req)

            ACTIVE_TUNNELS.append(tunnel(inact_tunnel.bss, inact_tunnel.apn, self.tid_out, self.tid_in, self.path_out, self.path_in))
            LOG.debug('TOPO MNGR: Inactive tunnel between ' + str(inact_tunnel.bss.name) + ' and ' + str(inact_tunnel.apn.name) +' put into active state!')

    def add_tunnel(self, _bss_, _apn_):
        """
        This method is called when new APN is discovered to connect it with all BSS stations via MAC Tunnels

        Keyword arguments:
            _bss_ -- object of bss class representing BSS node in topology
            _apn_ -- object of apn class representing APN in topology
            
        """
        self.bss = _bss_
        self.apn = _apn_
        self.tid_out = get_tid()
        self.tid_in  = get_tid()

        ##Attempt to find path between the two nodes
        ##If no path is found, tunnel is added to INACTIVE_TUNNELS and is attempted to recreate next time
        ##when new link between forwarders is up
        try:
            self.path_out = topo.get_tunnel(self.bss.name, self.apn.name)
            self.path_in  = topo.get_tunnel(self.apn.name, self.bss.name)
        except nx.NetworkXNoPath:
            LOG.warning("Warning: Couldn't find path, network might not be converged yet. Retrying when next forwarder joins network.")
            INACTIVE_TUNNELS.append(tunnel(self.bss,self.apn, self.tid_out, self.tid_in))
            return

        ##Set forwarding rules for all but last forwarder on the way OUT
        ##On first forwarder on the way OUT these rules are placed into table MAC_TUNNEL_TABLE while on 'dumb' forwarders it goes to 0
        dp = dpset.get(self.path_out[0].dpid)
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_dst=self.tid_out)
        actions = [parser.OFPActionOutput(self.path_out[0].port_out)]
        self.add_flow(dp, 300, match, actions, MAC_TUNNEL_TABLE)

        ##Rules for all 'dumb' forwardes on the way OUT
        for node in self.path_out[1:-1]:
            dp = dpset.get(node.dpid)
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_dst=self.tid_out)
            actions = [parser.OFPActionOutput(node.port_out)]
            self.add_flow(dp, 300, match, actions, 0)

        ##Last forwarder on the way OUT needs to set eth_dst to eth_addr of APN otherwise it won't be processed
        dp = dpset.get(self.path_out[-1].dpid)
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_dst=self.tid_out)
        actions = [ parser.OFPActionSetField(eth_dst=self.apn.eth_addr), parser.OFPActionOutput(self.path_out[-1].port_out)]
        self.add_flow(dp, 300, match, actions, 0)

        ##Here comes tunnel for way IN
        ##On first forwarder on the way IN these rules are placed into table MAC_TUNNEL_TABLE while on 'dumb' forwarders it goes to 0
        dp = dpset.get(self.path_in[0].dpid)
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_dst=self.tid_in)
        actions = [parser.OFPActionOutput(self.path_in[0].port_out)]
        self.add_flow(dp, 300, match, actions, MAC_TUNNEL_TABLE)

        ##Rules for 'dumb' forwarders
        for node in self.path_in[1:-1]:
            dp = dpset.get(node.dpid)
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_dst=self.tid_in)
            actions = [parser.OFPActionOutput(node.port_out)]
            self.add_flow(dp, 300, match, actions, 0)

        ##Last forwarder on the way IN sends packet to table #4 where it's matched based on active PDP CNTs
        dp = dpset.get(self.path_in[-1].dpid)
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_dst=self.tid_in)
        inst = [ parser.OFPInstructionGotoTable(OF_GPRS_TABLE_IN) ]
        req = parser.OFPFlowMod(datapath=dp, priority=500, match=match, instructions=inst, table_id=0)
        dp.send_msg(req)

        ACTIVE_TUNNELS.append(tunnel(self.bss,self.apn, self.tid_out, self.tid_in, self.path_out, self.path_in))
        LOG.debug('Tunnel between '+str(self.bss.name)+' and '+str(self.apn.name) + ' was set up.')
       
    def add_flow(self, dp, priority, match, actions, table=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
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

    #Testing
    def test_info(self,req):
        global dpset
        response = '<H1>Topology status DUMP</H1> </BR>'
        response += '<B>Dump created on: </B> ' + str(datetime.datetime.now())
        response += '</BR></BR><B>BSS edge forwarders list(decimal values):      </B> ' + str(BSS_EDGE_FORWARDER)
        response +=      '</BR><B>Internet edge forwarders list(decimal values): </B> ' + str(INET_EDGE_FORWARDER)

        response +=      '</BR><B>Active tunnels:   </B>'        
        for tunnel in ACTIVE_TUNNELS:
            response += '</BR>***Tunnel from: ' + tunnel.bss.name + ' to: ' + tunnel.apn.name + '***</BR>'
            for node in tunnel.path_out:
                response += str(node.dpid) + ' via port: ' + str(node.port_out) +', ' 
            response += '</BR>***Tunnel from: ' + tunnel.apn.name + ' to: ' + tunnel.bss.name + '***</BR>'
            for node in tunnel.path_in:
                response += str(node.dpid) + ' via port: ' + str(node.port_out) +', '

        response +=      '</BR><B>Inactive tunnels: </B>'
        for tunnel in INACTIVE_TUNNELS:
            response += '</BR>***Tunnel from: ' + tunnel.bss.name + ' to: ' + tunnel.apn.name + '***</BR>'
            for node in tunnel.path_out:
                response += str(node.dpid) + ' via port: ' + str(node.port_out) +', '
            response += '</BR>***Tunnel from: ' + tunnel.apn.name + ' to: ' + tunnel.bss.name + '***</BR>'
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


        if ACTIVE_TUNNELS or INACTIVE_TUNNELS:
            response += '<H2 style="color:green"> USER-PLANE TUNNELS ARE PRESENT </H2>'
        else:
            response += '<H2 style="color:orange"> USER-PLANE TUNNELS NOT PRESENT </H2>'

        LOG.debug('STATUS DUMP: Dumping Topology state at /test/info URL!')
        return (response)

    def dump_topology (self, req):
        LOG.debug('REST: TOPO DUMP: Dumping topology to JSON at /topology/dump ')
        return (Response(content_type='application/json', body=topo.dump(), headerlist=[('Access-Control-Allow-Origin', '*')]))
	
    def mod_gmm (self, req, cmd):
	LOG.debug('REST: mod_gmm: Modification of GMM called')	
	#parse GET parameters out of REST call
	body = urlparse.parse_qs(cmd)
	action = str(body.get('cmd'))[3:-2]
	
	#if the MS wants to attach
	if action[:3] == 'att':
	    #attach with IMSI	
	    if action == 'atti':
		imsi = str(body.get('imsi'))[3:-2]
		#check IMSI & our MCC+MNC
            	if imsi[:5] == MCC_MNC:
		    #if subscriber is from out network, let's find him in the HLR
                    if hlr.find_ms_by_imsi(imsi):
                    	ptmsi = hlr.create_mm_ctx(imsi)
                    	LOG.debug('REST: mod_gmm: Attach successful with IMSI: ' + imsi)
			return Response(status=200, content_type='application/json', body='{"cmd":"atti","result":"success", "imsi":"'+imsi+'","p-tmsi":"'+ptmsi+'"}')
		    #unknown IMSI
                    else:
                    	LOG.debug('REST: mod_gmm: Attach not successful with IMSI: ' + imsi)
                    	#return Response(status=500, content_type='text', body='"IMSI unknown in local HLR"')
			return Response(status=200, content_type='application/json', body='{"cmd":"atti","result":"fail", "imsi":"'+imsi+'"}')
	   	#subscriber is roaming
	        else:
                    LOG.debug("REST: mod_gmm: IMSI not local, asking remote controller")
                    #ask another controller
                    if roaming_partner_exists(imsi):
		        LOG.debug("REST: mod_gmm: Roaming partner found for IMSI: " + imsi) 
			url = ROAMING_PARTNERS[imsi[:5]]
			roaming_approved = get_roaming_data('imsi', imsi, 'att', url)
		    else:
		        LOG.debug("REST: mod_gmm: Roaming partner does not exist for IMSI: " + imsi) 
			#return Response(status=500, content_type='text', body='"No remote HLR found for IMSI: '+imsi+'"')	
			return Response(status=200, content_type='application/json', body='{"cmd":"atti","result":"fail","imsi":"'+imsi+'"}')			
		    if roaming_approved:
			ptmsi = hlr.create_mm_ctx(roaming_approved)
                    	LOG.debug('REST: mod_gmm: Roaming attach permitted for IMSI: ' + imsi)
			return Response(status=200, content_type='application/json', body='{"cmd":"atti","result":"success","imsi":"'+imsi+'","p-tmsi":"'+ptmsi+'"}')

                    else:
                    	LOG.debug('REST: mod_gmm: Roaming attach not permitted / IMSI not existing')
                    	#return Response(status=500, content_type='text', body='"IMSI unknown in remote HLR or roaming not permitted"')
			return Response(status=200, content_type='application/json', body='{"cmd":"atti","result":"fail","imsi":"'+imsi+'"}')
	    #attach with P-TMSI and old RAI
	    elif action == 'attp':
		p_tmsi = str(body.get('p-tmsi'))[3:-2]	
		old_rai = str(body.get('rai'))[3:-2]
	   	rai = old_rai.split('-')
		
		#if MNC is one digit long, we prepend a zero to it
		if len(rai[1]) == 1:
			rai[1] = '0' + rai[1]
		#combine MCC + MNC
		net_id = rai[0] + rai[1]
		
		#check of old RAI is local and find the IMSI for the P-TMSI
		if net_id == MCC_MNC: 
		    imsi = hlr.find_mm_ctx_by_ptmsi(p_tmsi)
		    if imsi:
			#check if IMSI is local?
			if imsi[:5] == MCC_MNC:
			    ptmsi = hlr.create_mm_ctx(imsi)
			    return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"success","imsi":"'+imsi+'","p-tmsi":"'+ptmsi+'"}')
		    	#contact roaming partner's controller
			else:
			    if roaming_partner_exists(imsi):
                        	LOG.debug("REST: mod_gmm: Roaming partner found for IMSI: " + imsi)
				url = ROAMING_PARTNERS[imsi[:5]]
                        	roaming_approved = get_roaming_data('imsi', imsi, 'att', url)
		    	        if roaming_approved:
				    ptmsi = hlr.create_mm_ctx(roaming_approved)
				    LOG.debug('REST: mod_gmm: Roaming attach permitted for IMSI: ' + roaming_approved)
				    return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"success","imsi":"'+imsi+'","p-tmsi":"'+ptmsi+'"}')
		    	        else:
				    return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"fail","p-tmsi":"'+p_tmsi+'"}')
			    else:
				LOG.debug("REST: mod_gmm: Roaming partner does not exist for IMSI: " + imsi)
				return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"fail","p-tmsi":"'+p_tmsi+'"}')
		    #P-TMSI unknown in local HLR, respond with error
		    else:
			return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"fail","p-tmsi":"'+p_tmsi+'"}')
		else:
		    #the old RAI is foreign, try to get IMSI from the foreign controller
		    if roaming_partner_exists(net_id):
                        LOG.debug("REST: mod_gmm: Roaming partner found for RAI: " + old_rai)
			url = ROAMING_PARTNERS[net_id]
                        imsi = get_roaming_data('p-tmsi', p_tmsi, 'att', url)
		    else:
                        LOG.debug("REST: mod_gmm: Roaming partner does not exist for P-TMSI: " + p_tmsi)
                       	return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"fail","p-tmsi":"'+p_tmsi+'"}')
		    #if the subscriber is known in remote controller 
		    if imsi:
			#check if IMSI is local
                        LOG.debug('REST: mod_gmm: IMSI found for P-TMSI: ' + p_tmsi)
            		if imsi[:5] == MCC_MNC:
		    	    #if subscriber is from our network, let's find him in the HLR
                    	    if hlr.find_ms_by_imsi(imsi):
                    	        ptmsi = hlr.create_mm_ctx(imsi)
                    		LOG.debug('REST: mod_gmm: Attach successful with IMSI: ' + imsi)
				return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"success", "imsi":"'+imsi+'","p-tmsi":"'+ptmsi+'"}')
		    	    #unknown IMSI
                    	    else:
                    	        LOG.debug('REST: mod_gmm: Attach not successful with IMSI: ' + imsi)
			        return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"fail", "p-tmsi":"'+p_tmsi+'"}')
                        #get roaming permission from HPLMN of the MS
			elif roaming_partner_exists(imsi):
                            LOG.debug("REST: mod_gmm: Roaming partner found for IMSI: " + imsi)
                            #if IMSI is from the same PLMN like P-TMSI, we don't need to ask the same controller again
			    if imsi[:5] == net_id:
				return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"success","imsi":"'+imsi+'","p-tmsi":"'+ptmsi+'"}')
			    url = ROAMING_PARTNERS[imsi[:5]]
			    roaming_approved = get_roaming_data('imsi', imsi, 'att', url)
		    	    if roaming_approved:
				ptmsi = hlr.create_mm_ctx(roaming_approved)
				LOG.debug('REST: mod_gmm: Roaming attach permitted for IMSI: ' + roaming_approved)
				return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"success","imsi":"'+imsi+'","p-tmsi":"'+ptmsi+'"}')
		    	    else:
				return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"fail","p-tmsi":"'+p_tmsi+'"}')
			else:
			    LOG.debug("REST: mod_gmm: Roaming partner does not exist for IMSI: " + imsi)
			    return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"fail","p-tmsi":"'+p_tmsi+'"}')
		    #IMSI unknown
                    else:
			LOG.debug('REST: mod_gmm: Roaming attach not permitted / IMSI not existing')
			return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"fail","p-tmsi":"'+p_tmsi+'"}')
	    #unknown type of attach	
	    else:
		return Response(status=500, content_type='text', body='"Error in URI"')

	#if MS wants to detach
	elif action == 'det':
	    p_tmsi = str(body.get('p-tmsi'))[3:-2]
	    
	    if hlr.find_mm_ctx_by_ptmsi(p_tmsi):
		hlr.delete_mm_ctx(p_tmsi)
		return Response(status=200, content_type='text', body='"Detach successful for P-TMSI: '+ p_tmsi +'"')
	    #XXX: tear down active tunnels if any
	    #XXX: notify home controller if the MS is foreign
	    return Response(status=500, content_type='text', body='"Subscriber unknown."')
	
	#if MS wants to perform an inter SGSN RAU
	elif action == 'rau':
		#XXX: add support for inter SGSN RAU
		return Response(status=500, content_type='text', body='"Feature not implemented yet."')
	
	#unknown action
	else:
	    return Response(status=500, content_type='text', body='"Error in URL"')
    
    def mod_roam_mm (self, req, cmd):
	
	LOG.debug('REST: mod_roam_mm: Modification of roaming GMM called')
        #parse GET parameters out of REST call
        body = urlparse.parse_qs(cmd)
        action = str(body.get('cmd'))[3:-2]
        
        if action[:3] == 'att':	
	    ##if our subscriber wants to attach in a VPLMN with IMSI
	    if action == 'atti':
	        imsi = str(body.get('imsi'))[3:-2]
		#validate if IMSI is local
		if imsi[:5] != MCC_MNC:
		    return Response(status=200, content_type='application/json', body='{"cmd":"atti","result":"fail", "imsi":"'+imsi+'"}') 
	   	#find MS in HLR 
		if hlr.find_ms_by_imsi(imsi):
	   	#add MS to a list of ACTIVE ROAMING SUBSCRIBERS
		    hlr.active_roaming_subscribers.append(imsi);
		    return Response(status=200, content_type='application/json', body='{"cmd":"atti","result":"success", "imsi":"'+imsi+'"}')
	    	else:
		    return Response(status=200, content_type='application/json', body='{"cmd":"atti","result":"fail", "imsi":"'+imsi+'"}')
	    
	    ##if a subscriber wants to attach in a VPLMN with P-TMSI generated in this PLMN
	    elif action == 'attp':	
		ptmsi = str(body.get('p-tmsi'))[3:-2]
		imsi = hlr.find_mm_ctx_by_ptmsi(ptmsi)
		if imsi:
		    if imsi == MCC_MNC:
			hlr.active_roaming_subscribers.append(imsi)
		    return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"success", "imsi":"'+imsi+'"}')
		else:
		    return Response(status=200, content_type='application/json', body='{"cmd":"attp","result":"fail", "p-tmsi":"'+ptmsi+'"}')
	
	elif action == 'det':
	    #XXX tear the active tunnels down
	    imsi = str(body.get('imsi'))[3:-2]
	    if imsi in hlr.active_roaming_subscribers:
		hlr.ctive_roaming_subscribers.remove(imsi)
	        return Response(content_type='application/json', body='{"imsi":"'+imsi+'"}')
	    return Response(status=500, content_type='text', body='"IMSI unknown in remote HLR"')
	else:
	    return Response(status=500, content_type='text', body='"Error in URL"')
	
    def mod_roam_sm (self, req, cmd):
	LOG.debug('REST: mod_roam_sm: Modification of roaming SM called')
	
	#XXX verify if suffiecient
	body = urlparse.parse_qs(cmd)
        action = str(body.get('cmd'))[3:-2]
	imsi = str(body.get('imsi'))[3:-2]	
	apn = str(body.get('apn'))[3:-2]

	#if user is not attached in the roaming network - no Session Management work possible
	if imsi not in hlr.active_remote_subscribers:
	    return Response(status=500, content_type='text', body='"IMSI not attached"')		

	#PDP context activation
	if action == 'add':
	    
	    #find path from roaming forwarder to the APN and back
	    tid_out=None
            tid_in=None
            path_in=None
            path_out=None

            ## We find tunnel that matches criteria from Activate PDP context request
            for act_tunnel in ACTIVE_TUNNELS:
                if start == act_tunnel.bss.name and end == act_tunnel.apn.name:
                    tid_out = act_tunnel.tid_out
                    tid_in = act_tunnel.tid_in
                    path_in =  act_tunnel.path_in
                    path_out = act_tunnel.path_out
                    LOG.debug('REST: mod_roam_sm: Tunnel was found')
                    break
	    
	    #XXX verify return a HTTP response to the controller if required tunnel doesn't exist
            if tid_out == None or tid_in == None or path_in == None or path_out == None:
                LOG.error('REST: mod_roam_sm: ERROR: No suitable tunnel for given PDP was found')
		return Response(status=500, content_type='text', body='"Tunnel not found"')
	    
            ## IP address is picked, in case there is no left, method ends and returns Internal Error HTTP response to caller
            if len(IP_POOL) == 0:
                LOG.error('REST: mod_roam_sm: ERROR: We are out of IP addresses') 
                return Response(status=500, content_type='text',body='"Out of IPs"')
	    
            #assign an IP address from the pool
            client_ip=IP_POOL.pop()

	    #XXX: create some sort of data structure similar to ACTIVE_CONTEXTS.append	    
	    #XXX ACTIVE ROAMING CONTEXTS or just a dictionary	     

	    #WAY OUT - match all traffic coming from interface connected to roaming partner's network and send it to the APN
	    #each PDP ctx is assigned a different IP address, so we can identify the ctx by matching it
            dp = self.dpset.get(path_out[0].dpid)
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = parser.OFPMatch(in_port=path_in[-1].port_out,
            			    eth_type=0x0800,
                                    ipv4_src=client_ip)	    
	    actions = [parser.OFPActionSetField(eth_dst=self.apn.eth_addr),  parser.OFPActionOutput(path_out[-1].port_out)]
	    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
	    req = parser.OFPFlowMod(datapath=dp, priority=400, match=match, instructions=inst, table_id = 0)
	    dp.send_msg(req)
            
	    #XXX check  
	    ##On the way IN we need to match packet on both first and last forwarder - it is the same forwarder in our topology
            ##for first in_port match aplies same rule as on the way out: in_port=path_out[-1].port_out
            dp = self.dpset.get(path_in[0].dpid)
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = parser.OFPMatch(in_port=path_out[-1].port_out,
                                    eth_type=0x0800,
                                    ipv4_dst=client_ip)
	    actions = [ parser.OFPActionOutput(path_in[-1].port_out)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            req = parser.OFPFlowMod(datapath=dp, priority=400, match=match, instructions=inst, table_id = 0)
            dp.send_msg(req)
	    
	    return (Response(content_type='application/json', body='{"address":"'+client_ip+'"}'))

	elif action == 'del':
	#XXX: add support for tunnel teardown
	    return Response(status=500, content_type='text', body='"Feature not implemented yet"')

	else:
	    return Response(status=500, content_type='text', body='"Error in URL"')

    def mod_sm (self, req, cmd):
        LOG.debug('REST: mod_sm: Modification of SM called')
        #parsing GET parameters out of REST call
        body = urlparse.parse_qs(cmd)
        action = str(body.get('cmd'))[3:-2]
	start = str(body.get('rai'))[3:-2]
        end = str(body.get('apn'))[3:-2]
        imsi = str(body.get('imsi'))[3:-2]
        bvci = int(str(body.get('bvci'))[3:-2])
        tlli = int(str(body.get('tlli'))[3:-2], 16)
        drx_param = int(str(body.get('drx_param'))[3:-2], 16)
        sapi = int(str(body.get('sapi'))[3:-2])
        nsapi = int(str(body.get('nsapi'))[3:-2])
	
	#verify if the MS is attached
	if not (hlr.find_mm_ctx_by_imsi(imsi)): 
	    LOG.error('REST: mod_sm: ERROR: Subscriber with IMSI: ' + imsi + ' not attached in controller')
	    return Response(status=500, content_type='text', body='"Subscriber not attached in controller. No SM actions possible."')	

	if action == 'add':
            tid_out=None
            tid_in=None
            path_in=None
            path_out=None
		
	    client_ip = ''
	  
	    #verify if IMSI is local. If no, find a tunnel to roaming forwarder, create rules for this MS and ask remote controller to build tunnels
	    if imsi[:5] != MCC_MNC:
		#store the APN		
		apn = end
		#find tunnel leading to the HPLMN of the roaming MS
		for roaming_apn in ROAMING_APN_POOL:
		    if roaming_apn.name == imsi[:5]:
			end = roaming_apn.name
			break

		#if tunnels/rules are not created in remote controller, return IP to the pool and respond with error
		client_ip = get_roaming_tunnel(action, imsi, apn) 
		if not client_ip: 
		    return Response(status=500, content_type='text', body='"Tunnel not found"')    	
            
            ## We find tunnel that matches criteria from Activate PDP context request
            for act_tunnel in ACTIVE_TUNNELS:
                LOG.debug('REST: mod_sm: start: '+ act_tunnel.bss.name + ' end: '+act_tunnel.apn.name)
		if start == act_tunnel.bss.name and end == act_tunnel.apn.name:
                    tid_out = act_tunnel.tid_out
                    tid_in = act_tunnel.tid_in
                    path_in =  act_tunnel.path_in
                    path_out = act_tunnel.path_out
                    LOG.debug('REST: mod_sm: Tunnel was found')
                    break
	    
	    #XXX verify return a HTTP response to vGSN if required tunnel doesn't exist
            if tid_out == None or tid_in == None or path_in == None or path_out == None:
                LOG.error('REST: mod_sm: ERROR: No suitable tunnel for given PDP was found')
		return Response(status=500, content_type='text', body='"Tunnel not found"')
	
            ## IP address is picked, in case there is no left, method ends and returns Internal Error HTTP response to caller
            if len(IP_POOL) == 0:
                LOG.error('REST: mod_sm: ERROR: We are out of IP addresses') 
                return Response(status=500, content_type='text',body='"Out of IPs"')
	    
            #if there is no IP address assigned, assign one
	    if len(client_ip) == 0:	    
            	client_ip=IP_POOL.pop()
	    
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
     
	    #last forwarder of the path
            dp = self.dpset.get(path_in[-1].dpid)
            parser = dp.ofproto_parser
            ofp = dp.ofproto
        
            ##XXX:Setfield eth_dst is set to the MAC address of the BSS simulator (bss1/bss2 interface)
	    ##to work with our BTS, eth_dst has to be set to our BTS's MAC address - eth_dst='00:d0:cc:08:02:ba'
            ##Last forwarder machtes Clients IP to push appropriate GPRS headers and determine port_out
            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_dst=client_ip)
            actions=[ GPRSActionPushGPRSNS(bvci, tlli, sapi, nsapi, drx_param, imsi),
                      GPRSActionPushUDPIP(sa=VGSN_IP, da=BSS_IP, sp=VGSN_PORT, dp=BSS_PORT),
                      parser.OFPActionSetField(eth_dst=BSS_MAC),
		     # parser.OFPActionSetField(eth_src=VGSN_MAC),
                      parser.OFPActionOutput(path_in[-1].port_out)]
            inst=[ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
 
            req = parser.OFPFlowMod(datapath=dp, priority=100, match=match, instructions=inst, table_id = OF_GPRS_TABLE_IN)
            dp.send_msg(req)

            return (Response(content_type='application/json', body='{"address":"'+client_ip+'","dns1":"8.8.8.8","dns2":"8.8.8.8"}'))
	
	#XXX:add support for PDP CTX deactivation
	elif action == 'del':
            #TODO:in case on CNT deactivation, return IP to pool
	    #TODO: remove rules from forwarders
	    #XXX notify roaming partner's controller
	    return

	#unknown action, respond with error
	else:
	    return (Response(status=500, content_type='text', body='"IMSI unknown in local HLR"'))
	
    def add_flow(self, dp, priority, match, actions, table = 0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, table_id=table, match=match, instructions=inst)
        dp.send_msg(mod)

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
