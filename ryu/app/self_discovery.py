from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3_parser
from ryu.controller import ofp_event
from ryu.controller import handler
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
import inspect
import array
import json
import ast

class Hello(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(Hello, self).__init__(*args, **kwargs)
        switchList = []
        self.dpset=dpset
         
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

    @set_ev_cls(ofp_event.EventOFPPacketIn)
    def _packet_in(self, ev):
      
        nieghbourDPID=self._get_icmp_data(packet.Packet(array.array('B', ev.msg.data)),'dpid')
        neighbourPort=self._get_icmp_data(packet.Packet(array.array('B', ev.msg.data)),'port_out')
        print('Som',ev.msg.datapath.id,
              ', dostal som spravu na porte: ',ev.msg.match['in_port'], 
              ' od cisla:',nieghbourDPID,
              ' ktory ma ma pripojeneho na porte',neighbourPort)
        #print(ev.msg.data)

    @set_ev_cls(ofp_event.EventOFPStateChange)
    def switch_woke_up(self, ev):
      
        dp = ev.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        # zmazme zo switchu vsetky pravidla
        req = parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE)
        dp.send_msg(req)

        # no_match ide na controller a flood von
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst='0.0.0.2')
        actions = [ parser.OFPActionOutput(ofp.OFPP_CONTROLLER) ]
        self.add_flow(dp, 100, match, actions) 

        if ev.state == handler.MAIN_DISPATCHER:
            #print('som up ',dp.id)
            #self._ping(dp,1)
            for var in dp.ports:
                if var != (ofp.OFPP_CONTROLLER+1):
                    self._ping(dp,var)
                    #print(var, ofp.OFPP_CONTROLLER)
                #print('~~~~~~~~~~~~~~~~~~debug~~~~~~~~~~~~~~~~~~~~~~~~~~~~', inspect.getmembers(dp))

    def _get_icmp_data(self, pkt, req):

        payload = ''
        for p in pkt:
            if p.protocol_name == 'icmp':
                for char in p.data.data:
                    payload+=(chr(char))
        slovnik = ast.literal_eval(payload.rstrip('\0'))
        return(slovnik.get(req))


#  @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
#  def _packet_in_handler(self, ev):
#    dp = ev.msg.datapath
#    ofp = dp.ofproto
#    parser = dp.ofproto_parser
#
#    # odkial a co nam doslo?
#    in_port = ev.msg.match['in_port']
#    pkt = packet.Packet(ev.msg.data)
#    eth = pkt.get_protocols(ethernet.ethernet)[0]
#    self.logger.info("%s -> port%s at dpid=%s", eth.src, in_port, dp.id)
#
#    # naucime sa, ze dana mac adresa je za portom odkial sa ozvala
#    match = parser.OFPMatch(eth_dst=eth.src)
#    actions = [parser.OFPActionOutput(in_port)]
#    self.add_flow(dp, 1, match, actions)
#
    def add_flow(self, dp, priority, match, actions):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)

