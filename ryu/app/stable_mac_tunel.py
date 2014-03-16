from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3_parser
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

#Reprezntuje uzol(forwarder) z ktorych sa sklada tunel 
class node:
  def __init__(self, dpid, port_out):
    self.dpid = dpid
    self.port_out = port_out

#Tunel ma svoje ID v tvare MAC adresy, podmienku(toto sa bude 100% menit na nieco ine), a zoznam uzlov ktorymi prechadza
class tunnels:
  def __init__(self, TID, condition, *n):
    self.TID = TID
    self.nodes = []
    for var in n:
      self.nodes.append(var)
    self.condition = condition

class Hello(app_manager.RyuApp):
  def __init__(self, *args, **kwargs):
    super(Hello, self).__init__(*args, **kwargs)
    #zatial staticky definovane tunely
    self.t = [tunnels('42:42:42:42:42:42', 0x0800, node(1,2), node(2,1)),
              tunnels('42:42:42:42:42:43', 0x0800, node(2,2), node(1,1)),
              tunnels('ab:ab:ab:ab:ab:ab', 0x0806, node(1,3), node(3,2), node(2,1)),
              tunnels('ab:ab:ab:ab:ab:ac', 0x0806, node(2,3), node(3,1), node(1,1))]

  @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
  def switch_features_handler(self, ev):
    dp = ev.msg.datapath
    ofp = dp.ofproto
    parser = dp.ofproto_parser
    next_table = 0
    # zmazme zo switchu vsetky pravidla
    req = parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE)
    dp.send_msg(req)
    #vytvaranie flow tabuliek na forwarderoch podla definovanych tunelov

    #pre kazdy forwarder sa prechadza celym polom tunelov
    for var in self.t:
      
      #ak je forwarder prvim v zozname musi mat vykonat aj zmenu MAC adresy
      if var.nodes[0].dpid == dp.id:
        
        #TODO:ohackovat condition aby ich mohlo byt pre tunel viac a aby sa dali rozumne vlozit do parser.OFPMatch()
        #TODO:prerobit tak aby tunel nemusel zacinat v porte jedna, pravdepodobne zmenit strukturu aby mal prvy node definovany aj in_port
        match = parser.OFPMatch(eth_type=var.condition, in_port=1)
        actions = [ parser.OFPActionSetField(eth_src=var.TID), parser.OFPActionOutput(var.nodes[0].port_out, 0) ]
        self.add_flow(dp, next_table, match, actions)
        next_table += 1
      
      #potom sa prejdu vsetky ostatne 'ne-prve' forwarderi v tunely na ktorych sa vytvaraju uz len jednoduche forwardovacie pravidla
      for var_nodes in var.nodes[1::1]:
        
        if var_nodes.dpid == dp.id:
          
          match = parser.OFPMatch(eth_src=(var.TID))
          actions = [ parser.OFPActionOutput(var_nodes.port_out, 0) ]
          self.add_flow(dp, next_table, match, actions)
          next_table += 1
  
  #_packet_in_handler sa nepouziva ale nejdem ho mazat keby sa zisiel neskor
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

  def add_flow(self, dp, priority, match, actions):
    ofp = dp.ofproto
    parser = dp.ofproto_parser

    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
    dp.send_msg(mod)
