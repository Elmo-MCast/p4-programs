
// Global constants

#define NUM_SPINES_PER_CORE     4

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

// --- Elmo header types ---

header_type elmo_type_t {
    fields {
        type_ : 1;
    }
}

header_type elmo_downstream_core_p_rule_t {
    fields {
        bitmap : NUM_SPINES_PER_CORE;
    }
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
        VXLAN_VNI_ELMO : parse_elmo_type;
        default : ingress;
    }
}

// -------------------------
// --- Parse Elmo header ---
// -------------------------

// --- Parse Elmo Type
header elmo_type_t elmo_type;

parser parse_elmo_type {
    extract(elmo_type);
    return parse_elmo_downstream_core_p_rule;
}

// --- Parse Downstream Core P-Rule
header elmo_downstream_core_p_rule_t elmo_downstream_core_p_rule;

parser parse_elmo_downstream_core_p_rule {
    extract(elmo_downstream_core_p_rule);
    return ingress;
}

// ----------------------------
// Match-action table functions
// ----------------------------

// Note: we only implement Elmo-related match-action logic here.

@pragma extern
action bitmap_port_select(bitmap, multipath) {}  // The extern action for bitmap-based port selection

action elmo_downstream_core_p_rule_act() {
    bitmap_port_select(elmo_downstream_core_p_rule.bitmap, 0);
}

table elmo_downstream_core_p_rule_tbl {
    actions {
        elmo_downstream_core_p_rule_act;
    }
    size : 1;
}

control ingress {
    if (valid(elmo_type)) {
        apply(elmo_downstream_core_p_rule_tbl);
    }
}

action elmo_invalidate_core_p_rules_when_going_downstream_act() {
    remove_header(elmo_downstream_core_p_rule);
    modify_field(elmo_type.type_, 0);
}

table elmo_invalidate_core_p_rules_tbl { // popping p-rules based on egress port
    actions {
        elmo_invalidate_core_p_rules_when_going_downstream_act;
    }
    size : NUM_SPINES_PER_CORE;
}

control egress {
    if (valid(elmo_type)) {
        apply(elmo_invalidate_core_p_rules_tbl);
    }
}
