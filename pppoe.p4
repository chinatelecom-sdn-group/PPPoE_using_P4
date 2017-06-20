header_type eth_hdr {
	fields {
		dst : 48;
		src : 48;
		etype : 16;
	}
}

header_type pppoe_hdr{
    fields {
        version : 4;
        pppoe_type : 4;
        code : 8;
        session_id : 16;
        pppoe_length : 16;
        ppp_proto : 16;
    }
}
header_type ipv4_hdr{
    fields {
        version         : 4;
        ihl             : 4;
        diffserv        : 8;
        totalLen        : 16;
        identification  : 16;
        flags           : 3;
        fragOffset      : 13;
        ttl             : 8;
        protocol        : 8;
        hdrChecksum     : 16;
        srcAddr         : 32;
        dstAddr         : 32;
    }
}


header eth_hdr eth_head;
header pppoe_hdr pppoe_head;
header ipv4_hdr ipv4_head;

// Start with ethernet always.
parser start {
    return ethernet;    
}
parser ethernet {
    extract(eth_head);   // Start with the ethernet header
    return select(latest.etype) {
        0x8863:     pppoe;
        0x0800:     ipv4;
        0x8864:     ppp;
        default:    ingress;
    }
}
parser ppp{
    extract(pppoe_head);
    return select(latest.ppp_proto) {
        0x0021: ipv4;
        default: ingress;
    }
}
parser pppoe{
    extract(pppoe_head);
    return ingress;
}
parser ipv4{
    extract(ipv4_head);
    return ingress;
}
action fwd_act(port)
{
    modify_field(standard_metadata.egress_spec, port);
}
action removeppp_fwd(port ,ethsrc ,ethdst)
{
    modify_field(eth_head.etype, 0x0800);
    modify_field(eth_head.src, ethsrc);
    modify_field(eth_head.dst, ethdst);
    remove_header(pppoe_head);
    modify_field(standard_metadata.egress_spec, port);
}
action addppp_fwd(port,sessionid,ethsrc,ethdst){
    add_header(pppoe_head);
    modify_field(pppoe_head.version,1);
    modify_field(pppoe_head.pppoe_type,1);
    modify_field(pppoe_head.code,0);
    modify_field(pppoe_head.session_id,sessionid);
    modify_field(pppoe_head.pppoe_length,ipv4_head.totalLen+2);
    modify_field(pppoe_head.ppp_proto,0x0021);
    modify_field(eth_head.etype, 0x8864);
    modify_field(eth_head.src, ethsrc);
    modify_field(eth_head.dst, ethdst);
    modify_field(standard_metadata.egress_spec, port);
}
action drop_act()
{
    drop();
}
table ip_table{
    reads{
        ipv4_head.dstAddr : exact;
    }
    actions{
        addppp_fwd;
        drop_act;
    }
    size : 20000;
}
table ppp_table{
    reads{
        standard_metadata.ingress_port : exact;
    }
    actions{
        fwd_act;
        drop_act;
    }
    size : 10 ;
}
table core_table{
    reads{
        ipv4_head.srcAddr : exact;
    }
    actions{
        removeppp_fwd;
        drop_act;
    }
    size : 20000;
}

control ingress {
    if(eth_head.etype == 0x0800){
        apply(ip_table);
    }else{
        if(eth_head.etype == 0x8864 or eth_head.etype == 0x8863){
            if(pppoe_head.ppp_proto == 0x0021){
                apply(core_table);
            }else{
                apply(ppp_table);
            }
        }
    }
}


