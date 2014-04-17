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
import socket

BSS_PHY_PORT = 1
VGSN_PHY_PORT = 3
TUNNEL_PHY_PORT = 2

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


class GPRSControll(app_manager.RyuApp):
    active_contexts = []

    def __init__(self, *args, **kwargs):
        super(GPRSControll, self).__init__(*args, **kwargs)

        # gprs_ns.pcap obsahuje jeden aktivny PDP kontext
        # TODO: o tom ake kontexty mame (a na ktorom datapathe) sa budeme 
        # dozvedat dynamicky cez REST
        # zatial, kazdy datapath ma vsetky kontexty
        self.active_contexts.append( PDPContext(bvci=2, tlli=0xc5a4aeea, sapi=3, nsapi=5, tunnel_port=TUNNEL_PHY_PORT, tunnel_internet='00:00:00:00:00:01', tunnel_bss='00:00:00:00:00:02', ip='10.10.10.10') )

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
                        in_port=BSS_PHY_PORT,
                        ns_type=0, 
                        ns_bvci=pdp.bvci,
                        bssgp_tlli=pdp.tlli,
                        llc_sapi=pdp.sapi,
                        sndcp_nsapi=pdp.nsapi)
        actions = [ GPRSActionPopGPRSNS(), GPRSActionPopUDPIP() , parser.OFPActionOutput(port=tunnel) ]
        inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
        req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=10, match=match, instructions=inst);
        dp.send_msg(req)

		# v opacnom smere nam vypadavaju z tunelu nejake packety.. balime ich do gprsns a posielame na bss
        # TODO: (mato) prepisat tento match, malo by sa matchovat:
        #  - zdrojova a cielova mac adresa tunela
        #  - cielova IP adresa (podla adresy ktoru ma priradeny PDP kontext)
        match = parser.OFPMatch( 
                in_port=TUNNEL_PHY_PORT,
                eth_type=0x0800, 
                eth_src=pdp.tunnel_internet,
                eth_dst=pdp.tunnel_bss,
                ipv4_dst=pdp.ip)
        # TODO: (mato)
        # adresa 10.11.12.13  adresa VGSN
        # adresa 20.21.22.23 je adresa BSS 
        # sp by mal byt port ktory sa nejako dozvieme (z prveho pripojenia BSS na VGSN)
        # dp by mal byt port na ktorom pocuva BSS, tiez sa ho dozvieme z prveho pripojenia BSS
        #XXX: kontrolny traffic z BSS na VGSN by sa mal asi posielat aj do controlleru, na analyzu cisiel portov?? minimalne na zaciatku
        actions = [
            GPRSActionPushGPRSNS( bvci=pdp.bvci, tlli=pdp.tlli, sapi=pdp.sapi, nsapi=pdp.nsapi),
            GPRSActionPushUDPIP( sa=VGSN_IP, da=BSS_IP, sp=VGSN_PORT, dp=BSS_PORT),
            parser.OFPActionOutput( port=BSS_PHY_PORT ) ] 
        inst = [ parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions) ]
        req = parser.OFPFlowMod(datapath=dp, table_id=OF_GPRS_TABLE, priority=11, match=match, instructions=inst);
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
        for pdp in self.active_contexts:
            self.add_pdp_context(dp, pdp, TUNNEL_PHY_PORT)

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
