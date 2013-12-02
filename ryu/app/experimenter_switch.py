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

VGSN_PORT = 2
TUNNEL_PORT = 3

GPRS_SDN_EXPERIMENTER = int("0x42", 16)
OF_GPRS_TABLE = 2


class PDPContext:
    def __init__(self, bvci, tlli, sapi, nsapi, tunnel):
        self.bvci = bvci
        self.tlli = tlli
        self.sapi = sapi
        self.nsapi = nsapi
        #TODO: QoS a tunnel treba premysliet
        self.tunnel = tunnel


class GPRSControll(app_manager.RyuApp):
    active_contexts = []

    def __init__(self, *args, **kwargs):
        super(GPRSControll, self).__init__(*args, **kwargs)

        # gprs_ns.pcap obsahuje jeden aktivny PDP kontext
        # TODO: o tom ake kontexty mame (a na ktorom datapathe) sa budeme 
        # dozvedat dynamicky cez REST
        # zatial, kazdy datapath ma vsetky kontexty
        self.active_contexts.append( PDPContext(bvci=2, tlli=0xc5a4aeea, sapi=3, nsapi=5, tunnel=0) )

    def add_pdp_context(self, dp, pdp, tunnel):
        """ Add new flow rule to redirect user traffic into tunnel interface.
        
        Keyword arguments:
            dp -- datapath
            pdp -- pdp context
            tunnel -- outgoing interface number

        """

        print "add new OF rule to DP="+str(dp)

        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # pouzivatelsky packet s danymi parametrami tlacime do dodaneho tunelu
        match = parser.OFPMatch(
                        ns_type=0, 
                        ns_bvci=pdp.bvci,
                        bssgp_tlli=pdp.tlli,
                        llc_sapi=pdp.sapi,
                        sndcp_nsapi=pdp.nsapi)
        actions = [ parser.OFPActionOutput(port=tunnel) ]
        inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
        req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=100, match=match, instructions=inst);
        dp.send_msg(req)

    def on_inner_dp_join(self, dp):
        """ Add new inner (BSS side) forwarder joined our network.
        
        Keyword arguments:
            dp -- datapath

        """

        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # zmazme vsetky existujuce pravidla
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE))
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE, table_id=OF_GPRS_TABLE))

        ##########################
        # hlavna flow tabulka (0)

        # UDP 23000 je GPRS-NS
        inst = [ parser.OFPInstructionGotoTable(OF_GPRS_TABLE) ]
        match = parser.OFPMatch(eth_type=0x0800,ip_proto=inet.IPPROTO_UDP, udp_dst=23000)
        req = parser.OFPFlowMod(datapath=dp, priority=1, match=match, instructions=inst)
        dp.send_msg(req)

        #################
        # gprsns tabulka
        
        # ak je to nie je prvy SNDCP fragment pouzivatelskeho packetu, DROP
        match = parser.OFPMatch( sndcp_first_segment=0 )
        actions = [ ] 
        inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
        req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=0, match=match, instructions=inst)
        dp.send_msg(req)
        
        # ak je to prvy SNDCP fragment packetu s viac ako jednym fragmentom, ICMP a DROP
        match = parser.OFPMatch( sndcp_first_segment=1, sndcp_more_segments=1 )
        actions = [ GPRSActionHello() ]
        inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
        req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=0, match=match, instructions=inst)
        dp.send_msg(req)

        # konkretne user packety posunieme, kam ich treba
        #XXX: pravidla pridava funkcia add_pdp_context
        #TODO: pridat vsetky aktivne PDP kontexty
        for pdp in self.active_contexts:
            self.add_pdp_context(dp, pdp, TUNNEL_PORT)

        # vsetko ostatne je signalizacia - tlacime do vGSN
        actions = [ parser.OFPActionOutput(VGSN_PORT) ]
        inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
        req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=0, instructions=inst)
        dp.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #TODO: check if this is new switch and add it to list of switches
        self.on_inner_dp_join(ev.msg.datapath)


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
        ofproto_parser.msg_pack_into("!HHIBBxxxxxx", buf, offset+8, 
                self.subtype, self.bvci, self.tlli, self.sapi, self.nsapi)

class GPRSActionPopGPRSNS(GPRSAction):
    def __init__(self):
        super(GPRSActionPopGPRSNS,self).__init__(0x0002)

class GPRSActionPushIP(GPRSAction):
    def __init__(self, sa, da):
        super(GPRSActionPushIP,self).__init__(0x0003)
        self.len = 24
        self.sa = sa
        self.da = da

    def serialize(self, buf, offset):
        """ Serialize PushIP action into buffer. """
        super(GPRSActionPushIP,self).serialize(buf, offset)
        ofproto_parser.msg_pack_into("!HxxIIxxxx", buf, offset+8,
                self.subtype, self.sa, self.da)

class GPRSActionPopIP(GPRSAction):
    def __init__(self):
        super(GPRSActionPopIP,self).__init__(0x0004)

class GPRSActionPushUDP(GPRSAction):
    def __init__(self, sp, dp):
        super(GPRSActionPushUDP,self).__init__(0x0005)
        self.len = 16
        self.sp = sp
        self.dp = dp

    def serialize(self, buf, offset):
        """ Serialize PushUDP action into buffer. """
        super(GPRSActionPushUDP,self).serialize(buf, offset)
        ofproto_parser.msg_pack_into("!HHHxx", buf, offset+8,
                self.subtype, self.sa, self.da)

class GPRSActionPopUDP(GPRSAction):
    def __init__(self):
        super(GPRSActionPopUDP,self).__init__(0x0006)

class GPRSActionHello(GPRSAction):
    def __init__(self):
        super(GPRSActionHello,self).__init__(0x0100)

#    gprs_subtype = {'pushGPRSNS': '0x1', 'popGPRSNS': '0x2', 'pushIP': '0x3' , 'popIP': '0x4', 'pushUDP': '0x5', 'popUDP': '0x6', 'hello': '0x0100'}
