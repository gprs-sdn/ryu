from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3_parser
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_parser
import struct
import sys

match = 0

class Hello(app_manager.RyuApp):
  def __init__(self, *args, **kwargs):
    super(Hello, self).__init__(*args, **kwargs)

  @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
  def switch_features_handler(self, ev):
    dp = ev.msg.datapath
    ofp = dp.ofproto
    parser = dp.ofproto_parser
    global match

    # zmazme zo switchu vsetky pravidla
    req = parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE)
    dp.send_msg(req)

	# urobme hello a posleme vsade
    actions = [ 
			parser.OFPActionOutput(ofp.OFPP_FLOOD, 0),
			HelloAction()
			]
    inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
    #match = parser.OFPMatch(eth_type=0x800,ip_proto=0x11, udp_dst=23000)
    match = OFPExperimenterMatch()
    req = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
    dp.send_msg(req)

class HelloAction(ofproto_v1_3_parser.OFPActionExperimenter):
  def __init__(self):
    super(ofproto_v1_3_parser.OFPActionExperimenter, self).__init__()
    self.experimenter = int("0x42", 16)
    self.subtype = int("0x0100", 16)
    self.exp_struct = "!HHIHxxxxxx"
  
  def serialize(self, buf, offset):
    self.type = int("0xffff", 16)
    self.len = int("0x10", 16)
    ofproto_parser.msg_pack_into(self.exp_struct, buf, offset, self.type ,self.len, self.experimenter, self.subtype)

class OFPExperimenterMatch(ofproto_v1_3_parser.OFPMatch):
  def __init__(self):
    super(ofproto_v1_3_parser.OFPMatch, self).__init__()
    global match
    self.experimenter = int("0x42", 16)
    self.len =int("0x10", 16)
    self.OFPXMC = int("0xbabe", 16)
    self.OFPMT = int("0x01", 16)
    self.struct = "!HHIIHH"
    self.expMatch = int("0x01", 16)
    self.value = 0
    self.match = int(match)
    print(self.match)    
    
  def serialize(self, buf, offset):
  # ofproto_parser.msg_pack_into(self.struct, buf, offset, self.OFPMT, self.len, self.OFPXMC, self.experimenter, self.expMatch, self.value)
    ofproto_parser.msg_pack_into(self.struct, buf, offset, self.OFPMT, self.len, self.OFPXMC, self.experimenter, self.expMatch, self.value)   
    return self.len
