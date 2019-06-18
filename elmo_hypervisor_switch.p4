
// --------------------
// --- Header types ---
// --------------------

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}

header_type vxlan_t {
    fields {
        flags : 8;
        reserved : 24;
        vni : 24;
        reserved2 : 8;
    }
}

// --- Elmo header (combined) ---

header_type elmo_header_t {
    fields {
        data : *;
    }
    max_length : 32;
}

// ------------------------
// --- Parser functions ---
// ------------------------

parser start {
    return parse_ethernet;
}

// --------------------------------
// --- Parse outer VXLAN header ---
// --------------------------------

#define ETHERTYPE_IPV4 0x0800

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default : ingress;
    }
}

#define IP_PROTOCOLS_UDP 17

header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        IP_PROTOCOLS_UDP  : parse_udp;
        default : ingress;
    }
}

#define UDP_PORT_VXLAN 4789

header udp_t udp;

field_list udp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        8'0;
        ipv4.protocol;
        udp.length_;
        udp.srcPort;
        udp.dstPort;
        udp.length_;
        payload;
}

field_list_calculation udp_checksum {
    input {
        udp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field udp.checksum {
    update udp_checksum;
}

parser parse_udp {
    extract(udp);
    return select(latest.dstPort) {
        UDP_PORT_VXLAN  : parse_vxlan;
        default : ingress;
    }
}

#define VXLAN_VNI_ELMO 0xABCDEF

header vxlan_t vxlan;

parser parse_vxlan {
    extract(vxlan);
    return select(latest.vni) {
        VXLAN_VNI_ELMO : parse_elmo_header;
        default : parse_inner_ethernet;
    }
}

// -------------------------
// --- Parse Elmo header ---
// -------------------------

header elmo_header_t elmo_header;

parser parse_elmo_header {
    extract(elmo_header);
    return parse_inner_ethernet;
}

// --------------------------------
// --- Parse inner VXLAN Header ---
// --------------------------------

header ethernet_t inner_ethernet;

parser parse_inner_ethernet {
    extract(inner_ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_inner_ipv4;
        default: ingress;
    }
}

header ipv4_t inner_ipv4;

field_list inner_ipv4_checksum_list {
        inner_ipv4.version;
        inner_ipv4.ihl;
        inner_ipv4.diffserv;
        inner_ipv4.totalLen;
        inner_ipv4.identification;
        inner_ipv4.flags;
        inner_ipv4.fragOffset;
        inner_ipv4.ttl;
        inner_ipv4.protocol;
        inner_ipv4.srcAddr;
        inner_ipv4.dstAddr;
}

field_list_calculation inner_ipv4_checksum {
    input {
        inner_ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field inner_ipv4.hdrChecksum  {
    verify inner_ipv4_checksum;
    update inner_ipv4_checksum;
}

parser parse_inner_ipv4 {
    extract(inner_ipv4);
    return select(latest.protocol) {
        IP_PROTOCOLS_UDP  : parse_inner_udp;
        default: ingress;
    }
}

header udp_t inner_udp;

field_list inner_udp_checksum_list {
        inner_ipv4.srcAddr;
        inner_ipv4.dstAddr;
        8'0;
        inner_ipv4.protocol;
        inner_udp.length_;
        inner_udp.srcPort;
        inner_udp.dstPort;
        inner_udp.length_;
        payload;
}

field_list_calculation inner_udp_checksum {
    input {
        inner_udp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field inner_udp.checksum {
    update inner_udp_checksum;
}

parser parse_inner_udp {
    extract(inner_udp);
    return ingress;
}

// ----------------------------
// Match-action table functions
// ----------------------------

// Dummy control flow: in hypervisor switches (like PISCES), the control flow
// is specified at runtime, please see the accompanying .sh file

action dummy_action() {

}

table dummy_table {
    actions {
        dummy_action;
    }
    size: 1;
}

control ingress {
    apply(dummy_table);
}

control egress {
}
