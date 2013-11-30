from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3_parser
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_parser
from ryu.ofproto import inet
import struct
import sys 

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
			GPRSAction('hello')
			]
    inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
    match = parser.OFPMatch(eth_type=0x0800,ip_proto=inet.IPPROTO_UDP, udp_dst=23000, ns_type=0, ns_bvci=2, bssgp_tlli=0xc5a4aeea, llc_sapi=3, sndcp_nsapi=5)
    req = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
    dp.send_msg(req)

class GPRSAction(ofproto_v1_3_parser.OFPActionExperimenter):
  gprs_subtype = {'pushGPRSNS': '0x1', 'popGPRSNS': '0x2', 'pushIP': '0x3' , 'popIP': '0x4', 'pushUDP': '0x5', 'popUDP': '0x6', 'hello': '0x0100'}
  def __init__(self, action):
    super(ofproto_v1_3_parser.OFPActionExperimenter, self).__init__()
    self.experimenter = int("0x42", 16)
    self.subtype = int(self.gprs_subtype[action], 16)
    self.exp_struct = "!HHIHxxxxxx"
  
  def serialize(self, buf, offset):
    self.type = int("0xffff", 16)
    self.len = int("0x10", 16)
    ofproto_parser.msg_pack_into(self.exp_struct, buf, offset, self.type ,self.len, self.experimenter, self.subtype)

