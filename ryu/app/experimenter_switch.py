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

class Hello(app_manager.RyuApp):
  def __init__(self, *args, **kwargs):
    super(Hello, self).__init__(*args, **kwargs)

  @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
  def switch_features_handler(self, ev):
    dp = ev.msg.datapath
    ofp = dp.ofproto
    parser = dp.ofproto_parser
    exp = expAction(0x00000042)

    # zmazme zo switchu vsetky pravidla
    req = parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE)
    dp.send_msg(req)

    #Experimentalna Action
    match = parser.OFPMatch(icmpv4_type=8)
    actions = [ exp ]
    self.add_flow(dp, 0, match, actions)
    
    # broadcast sa flooduje
    #match = parser.OFPMatch(eth_dst='ff:ff:ff:ff:ff:ff')
    #actions = [ parser.OFPActionOutput(ofp.OFPP_FLOOD, 0) ]
    #self.add_flow(dp, 0, match, actions)

    # no_match ide na controller a flood von
    match = parser.OFPMatch()
    actions = [ parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER),
        parser.OFPActionOutput(ofp.OFPP_FLOOD, 0) ]
    self.add_flow(dp, 0, match, actions)  

  @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
  def _packet_in_handler(self, ev):
    dp = ev.msg.datapath
    ofp = dp.ofproto
    parser = dp.ofproto_parser

    
    # odkial a co nam doslo?
    in_port = ev.msg.match['in_port']
    pkt = packet.Packet(ev.msg.data)
    eth = pkt.get_protocols(ethernet.ethernet)[0]
    self.logger.info("%s -> port%s at dpid=%s", eth.src, in_port, dp.id)

    # naucime sa, ze dana mac adresa je za portom odkial sa ozvala
    match = parser.OFPMatch(eth_dst=eth.src)
    actions = [parser.OFPActionOutput(in_port)]
    self.add_flow(dp, 1, match, actions)

  def add_flow(self, dp, priority, match, actions):
    ofp = dp.ofproto
    parser = dp.ofproto_parser

    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
    dp.send_msg(mod)

class expAction(ofproto_v1_3_parser.OFPActionExperimenter):
 def __init__(self, experimenter, type_=None, len_=None):
  super(ofproto_v1_3_parser.OFPActionExperimenter, self).__init__()
  self.experimenter =int("0x42", 16)
  self.subtype = int("0x100", 16)
  self.exp_struct = "!HHIHIH"
  self.pad = 0
  
 def serialize(self, buf, offset, type= int("0xffff", 16), len= int("0x16", 16)):
  print(offset, sys.getsizeof(buf))
  ofproto_parser.msg_pack_into(self.exp_struct, buf, offset, type ,len, self.experimenter,self.subtype, self.pad, self.pad)
  print(offset, sys.getsizeof(buf))
  
