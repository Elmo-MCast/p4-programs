
// Global constants

#define SWITCH_ID               1
#define SPINE_ID_SIZE_in_BITS   3
#define LEAF_ID_SIZE_in_BITS    3

#define NUM_HOSTS_PER_LEAF      2
#define NUM_SPINES_PER_LEAF     2
#define NUM_LEAFS_PER_SPINE     2
#define NUM_CORES_PER_SPINE     2
#define NUM_SPINES_PER_CORE     4

// --------------------
// --- Header types ---
// --------------------

header_type intrinsic_metadata_t {
    fields {
        ingress_global_timestamp : 48;
        egress_global_timestamp : 48;
        mcast_grp : 16;
        egress_rid : 16;
    }
}
metadata intrinsic_metadata_t intrinsic_metadata;

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

header_type elmo_upstream_leaf_p_rule_t {
    fields {
        downstream_bitmap : NUM_HOSTS_PER_LEAF;
        upstream_bitmap : NUM_SPINES_PER_LEAF;
        multipath : 1;
        next_spine_p_rule : 1;
    }
}

header_type elmo_upstream_spine_p_rule_t {
    fields {
        downstream_bitmap : NUM_LEAFS_PER_SPINE;
        upstream_bitmap : NUM_CORES_PER_SPINE;
        multipath : 1;
        next_core_p_rule : 1;
    }
}

header_type elmo_downstream_core_p_rule_t {
    fields {
        bitmap : NUM_SPINES_PER_CORE;
    }
}

// Note: a downstream spine and leaf p_rule is a collection of a bitmap and ids.

header_type elmo_downstream_spine_head_p_rule_t {
    fields {
        bitmap : NUM_LEAFS_PER_SPINE;
        id : SPINE_ID_SIZE_in_BITS;
        next_id : 1;
        next_p_rule : 1;
        has_default_bitmap : 1;
    }
}

header_type elmo_downstream_spine_p_rule_t {
    fields {
        bitmap : NUM_LEAFS_PER_SPINE;
        id : SPINE_ID_SIZE_in_BITS;
        next_id : 1;
        next_p_rule : 1;
    }
}

header_type elmo_downstream_spine_last_p_rule_t {
    fields {
        bitmap : NUM_LEAFS_PER_SPINE;
        id : SPINE_ID_SIZE_in_BITS;
        next_id : 1;
    }
}

header_type elmo_downstream_spine_id_t {
    fields {
        id : SPINE_ID_SIZE_in_BITS;
        next_id : 1;
    }
}

header_type elmo_downstream_spine_last_id_t {
    fields {
        id : SPINE_ID_SIZE_in_BITS;
    }
}

header_type elmo_downstream_spine_bitmap_t {
    fields {
        bitmap : NUM_LEAFS_PER_SPINE;
    }
}

header_type elmo_downstream_spine_matching_bitmap_t {
    fields {
        bitmap : NUM_LEAFS_PER_SPINE;
        is_present : 1;
    }
}

header_type elmo_downstream_leaf_head_p_rule_t {
    fields {
        bitmap : NUM_HOSTS_PER_LEAF;
        id : LEAF_ID_SIZE_in_BITS;
        next_id : 1;
        next_p_rule : 1;
        has_default_bitmap : 1;
    }
}

header_type elmo_downstream_leaf_p_rule_t {
    fields {
        bitmap : NUM_HOSTS_PER_LEAF;
        id : LEAF_ID_SIZE_in_BITS;
        next_id : 1;
        next_p_rule : 1;
    }
}

header_type elmo_downstream_leaf_last_p_rule_t {
    fields {
        bitmap : NUM_HOSTS_PER_LEAF;
        id : LEAF_ID_SIZE_in_BITS;
        next_id : 1;
    }
}

header_type elmo_downstream_leaf_id_t {
    fields {
        id : LEAF_ID_SIZE_in_BITS;
        next_id : 1;
    }
}

header_type elmo_downstream_leaf_last_id_t {
    fields {
        id : LEAF_ID_SIZE_in_BITS;
    }
}

header_type elmo_downstream_leaf_bitmap_t {
    fields {
        bitmap : NUM_HOSTS_PER_LEAF;
    }
}

header_type elmo_downstream_leaf_matching_bitmap_t {
    fields {
        bitmap : NUM_HOSTS_PER_LEAF;
        is_matched : 1;
    }
}

header_type elmo_leaf_complete_bitmap_t {
    fields {
        bitmap : 4; // NUM_HOSTS_PER_LEAF + NUM_SPINES_PER_LEAF
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
        default : parse_inner_ethernet;
    }
}

// -------------------------
// --- Parse Elmo header ---
// -------------------------

// --- Parse Elmo type
header elmo_type_t elmo_type;

parser parse_elmo_type {
    extract(elmo_type);
    return select(latest.type_) {
        1       : parse_elmo_upstream_leaf_p_rule;
        default : parse_elmo_downstream_leaf_head_p_rule;
    }
}

// --- Parse upstream leaf p-rule
header elmo_upstream_leaf_p_rule_t elmo_upstream_leaf_p_rule;

parser parse_elmo_upstream_leaf_p_rule {
    extract(elmo_upstream_leaf_p_rule);
    return select(latest.next_spine_p_rule) {
        1       : parse_elmo_upstream_spine_p_rule;
        default : parse_inner_ethernet;
    }
}

// --- Parse upstream spine p-rule
header elmo_upstream_spine_p_rule_t elmo_upstream_spine_p_rule;

parser parse_elmo_upstream_spine_p_rule {
    extract(elmo_upstream_spine_p_rule);
    return select(latest.next_core_p_rule) {
        1       : parse_elmo_downstream_core_p_rule;
        default : parse_elmo_downstream_leaf_head_p_rule;
    }
}

// --- Parse downstream core p-rule
header elmo_downstream_core_p_rule_t elmo_downstream_core_p_rule;

parser parse_elmo_downstream_core_p_rule {
    extract(elmo_downstream_core_p_rule);
    return parse_elmo_downstream_spine_head_p_rule;
}

// --- Parse downstream spine p-rules

// ------ Parse head p-rule
header elmo_downstream_spine_head_p_rule_t elmo_downstream_spine_head_p_rule;

parser parse_elmo_downstream_spine_head_p_rule {
    extract(elmo_downstream_spine_head_p_rule);
    return select(latest.next_id, latest.next_p_rule, latest.has_default_bitmap) {
        0x4 mask 0x4 : parse_elmo_downstream_spine_head_p_rule_last_id;
        0x2 mask 0x2 : parse_elmo_downstream_spine_last_p_rule;
        0x1 mask 0x1 : parse_elmo_downstream_spine_default_bitmap;
        default      : parse_elmo_downstream_leaf_head_p_rule;
    }
}

header elmo_downstream_spine_last_id_t elmo_downstream_spine_head_p_rule_last_id;

parser parse_elmo_downstream_spine_head_p_rule_last_id {
    extract(elmo_downstream_spine_head_p_rule_last_id);
    return select(elmo_downstream_spine_head_p_rule.next_p_rule, elmo_downstream_spine_head_p_rule.has_default_bitmap) {
        0x2 mask 0x2 : parse_elmo_downstream_spine_last_p_rule;
        0x1 mask 0x1 : parse_elmo_downstream_spine_default_bitmap;
        default      : parse_elmo_downstream_leaf_head_p_rule;
    }
}

// ------ Parse p-rule #2 or the last one
header elmo_downstream_spine_last_p_rule_t elmo_downstream_spine_last_p_rule;

parser parse_elmo_downstream_spine_last_p_rule {
    extract(elmo_downstream_spine_last_p_rule);
    return select(latest.next_id, elmo_downstream_spine_head_p_rule.has_default_bitmap) {
        0x2 mask 0x2 : parse_elmo_downstream_spine_last_p_rule_last_id;
        0x1 mask 0x1 : parse_elmo_downstream_spine_default_bitmap;
        default      : parse_elmo_downstream_leaf_head_p_rule;
    }
}

header elmo_downstream_spine_last_id_t elmo_downstream_spine_last_p_rule_last_id;

parser parse_elmo_downstream_spine_last_p_rule_last_id {
    extract(elmo_downstream_spine_last_p_rule_last_id);
    return select(elmo_downstream_spine_head_p_rule.has_default_bitmap) {
        1       : parse_elmo_downstream_spine_default_bitmap;
        default : parse_elmo_downstream_leaf_head_p_rule;
    }
}

// ------ Parse default p-rule
header elmo_downstream_spine_bitmap_t elmo_downstream_spine_default_bitmap;

parser parse_elmo_downstream_spine_default_bitmap {
    extract(elmo_downstream_spine_default_bitmap);
    return parse_elmo_downstream_leaf_head_p_rule;
}

// --- Parse downstream leaf p-rules

metadata elmo_downstream_leaf_matching_bitmap_t elmo_downstream_leaf_matching_bitmap;

// ------ Parse head p-rule
header elmo_downstream_leaf_head_p_rule_t elmo_downstream_leaf_head_p_rule;

parser parse_elmo_downstream_leaf_head_p_rule {
    extract(elmo_downstream_leaf_head_p_rule);
    return select(latest.next_id, latest.next_p_rule, latest.has_default_bitmap, elmo_type.type_,
                  latest.id) { // Assuming LEAF_ID_SIZE_in_BITS = 12
        SWITCH_ID mask 0x07 : parse_elmo_downstream_leaf_head_p_rule_read_matching_bitmap;
        0x40 mask 0x40      : parse_elmo_downstream_leaf_head_p_rule_last_id;
        0x20 mask 0x20      : parse_elmo_downstream_leaf_last_p_rule;
        0x10 mask 0x10      : parse_elmo_downstream_leaf_default_bitmap;
        default             : parse_inner_ethernet;
    }
}

parser parse_elmo_downstream_leaf_head_p_rule_read_matching_bitmap {
    set_metadata(elmo_downstream_leaf_matching_bitmap.bitmap, elmo_downstream_leaf_head_p_rule.bitmap);
    set_metadata(elmo_downstream_leaf_matching_bitmap.is_matched, 1);
    return select(elmo_downstream_leaf_head_p_rule.next_id, elmo_downstream_leaf_head_p_rule.next_p_rule, elmo_downstream_leaf_head_p_rule.has_default_bitmap) {
        0x4 mask 0x4 : parse_elmo_downstream_leaf_head_p_rule_last_id;
        0x2 mask 0x2 : parse_elmo_downstream_leaf_last_p_rule;
        0x1 mask 0x1 : parse_elmo_downstream_leaf_default_bitmap;
        default      : parse_inner_ethernet;
    }
}

header elmo_downstream_leaf_last_id_t elmo_downstream_leaf_head_p_rule_last_id;

parser parse_elmo_downstream_leaf_head_p_rule_last_id {
    extract(elmo_downstream_leaf_head_p_rule_last_id);
    return select(elmo_downstream_leaf_head_p_rule.next_p_rule, elmo_downstream_leaf_head_p_rule.has_default_bitmap, elmo_type.type_,
                  latest.id) { // Assuming LEAF_ID_SIZE_in_BITS = 12
        SWITCH_ID mask 0x07 : parse_elmo_downstream_leaf_head_p_rule_last_id_read_matching_bitmap;
        0x20 mask 0x20      : parse_elmo_downstream_leaf_last_p_rule;
        0x10 mask 0x10      : parse_elmo_downstream_leaf_default_bitmap;
        default             : parse_inner_ethernet;
    }
}

parser parse_elmo_downstream_leaf_head_p_rule_last_id_read_matching_bitmap {
    set_metadata(elmo_downstream_leaf_matching_bitmap.bitmap, elmo_downstream_leaf_head_p_rule.bitmap);
    set_metadata(elmo_downstream_leaf_matching_bitmap.is_matched, 1);
    return select(elmo_downstream_leaf_head_p_rule.next_p_rule, elmo_downstream_leaf_head_p_rule.has_default_bitmap) {
        0x2 mask 0x2 : parse_elmo_downstream_leaf_last_p_rule;
        0x1 mask 0x1 : parse_elmo_downstream_leaf_default_bitmap;
        default      : parse_inner_ethernet;
    }
}

// ------ Parse p-rule #2 or the last one
header elmo_downstream_leaf_last_p_rule_t elmo_downstream_leaf_last_p_rule;

parser parse_elmo_downstream_leaf_last_p_rule {
    extract(elmo_downstream_leaf_last_p_rule);
    return select(latest.next_id, elmo_downstream_leaf_head_p_rule.has_default_bitmap, elmo_type.type_,
                  latest.id) { // Assuming LEAF_ID_SIZE_in_BITS = 12
        SWITCH_ID mask 0x07 : parse_elmo_downstream_leaf_last_p_rule_read_matching_bitmap;
        0x20 mask 0x20      : parse_elmo_downstream_leaf_last_p_rule_last_id;
        0x10 mask 0x10      : parse_elmo_downstream_leaf_default_bitmap;
        default             : parse_inner_ethernet;
    }
}

parser parse_elmo_downstream_leaf_last_p_rule_read_matching_bitmap {
    set_metadata(elmo_downstream_leaf_matching_bitmap.bitmap, elmo_downstream_leaf_last_p_rule.bitmap);
    set_metadata(elmo_downstream_leaf_matching_bitmap.is_matched, 1);
    return select(elmo_downstream_leaf_last_p_rule.next_id, elmo_downstream_leaf_head_p_rule.has_default_bitmap) {
        0x2 mask 0x2 : parse_elmo_downstream_leaf_last_p_rule_last_id;
        0x1 mask 0x1 : parse_elmo_downstream_leaf_default_bitmap;
        default      : parse_inner_ethernet;
    }
}

header elmo_downstream_leaf_last_id_t elmo_downstream_leaf_last_p_rule_last_id;

parser parse_elmo_downstream_leaf_last_p_rule_last_id {
    extract(elmo_downstream_leaf_last_p_rule_last_id);
    return select(elmo_downstream_leaf_head_p_rule.has_default_bitmap, elmo_type.type_,
                  latest.id) { // Assuming LEAF_ID_SIZE_in_BITS = 12
        SWITCH_ID mask 0x07 : parse_elmo_downstream_leaf_last_p_rule_last_id_read_matching_bitmap;
        1                   : parse_elmo_downstream_leaf_default_bitmap;
        default             : parse_inner_ethernet;
    }
}

parser parse_elmo_downstream_leaf_last_p_rule_last_id_read_matching_bitmap {
    set_metadata(elmo_downstream_leaf_matching_bitmap.bitmap, elmo_downstream_leaf_last_p_rule.bitmap);
    set_metadata(elmo_downstream_leaf_matching_bitmap.is_matched, 1);
    return select(elmo_downstream_leaf_head_p_rule.has_default_bitmap) {
        1       : parse_elmo_downstream_leaf_default_bitmap;
        default : parse_inner_ethernet;
    }
}

header elmo_downstream_leaf_bitmap_t elmo_downstream_leaf_default_bitmap;

parser parse_elmo_downstream_leaf_default_bitmap {
    extract(elmo_downstream_leaf_default_bitmap);
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

// Note: we only implement Elmo-related match-action logic here.

@pragma extern
action bitmap_port_select(bitmap, multipath) {}  // the extern action for bitmap-based port selection

metadata elmo_leaf_complete_bitmap_t elmo_leaf_complete_bitmap;

action elmo_upstream_leaf_p_rule_act() {
    shift_left(elmo_leaf_complete_bitmap.bitmap, elmo_upstream_leaf_p_rule.downstream_bitmap, NUM_SPINES_PER_LEAF);
    bit_or(elmo_leaf_complete_bitmap.bitmap, elmo_leaf_complete_bitmap.bitmap, elmo_upstream_leaf_p_rule.upstream_bitmap);
    bitmap_port_select(elmo_leaf_complete_bitmap.bitmap, elmo_upstream_leaf_p_rule.multipath);
}

table elmo_upstream_leaf_p_rule_tbl {
    actions {
        elmo_upstream_leaf_p_rule_act;
    }
    size : 1;
}

action elmo_downstream_leaf_p_rule_act() {
    shift_left(elmo_leaf_complete_bitmap.bitmap, elmo_downstream_leaf_matching_bitmap.bitmap, NUM_SPINES_PER_LEAF);
    bitmap_port_select(elmo_leaf_complete_bitmap.bitmap, 0);
}

table elmo_downstream_leaf_p_rule_tbl {
    actions {
        elmo_downstream_leaf_p_rule_act;
    }
    size : 1;
}

action elmo_downstream_leaf_s_rule_act(mcast_group) {
    modify_field(intrinsic_metadata.mcast_grp, mcast_group);
}

table elmo_downstream_leaf_s_rule_tbl {
    reads {
        inner_ipv4.dstAddr : exact;  // the group identifier
    }
    actions {
        elmo_downstream_leaf_s_rule_act;
    }
    size : 10000;
}

action elmo_downstream_leaf_default_p_rule_act() {
    shift_left(elmo_leaf_complete_bitmap.bitmap, elmo_downstream_leaf_default_bitmap.bitmap, NUM_SPINES_PER_LEAF);
    bitmap_port_select(elmo_leaf_complete_bitmap.bitmap, 0);
}

table elmo_downstream_leaf_default_p_rule_tbl {
    actions {
        elmo_downstream_leaf_default_p_rule_act;
    }
    size : 1;
}

control ingress {
    if (valid(elmo_type)) {
        if (valid(elmo_upstream_leaf_p_rule)) {
            apply(elmo_upstream_leaf_p_rule_tbl);
        } else {
            if (elmo_downstream_leaf_matching_bitmap.is_matched == 1) {
              apply(elmo_downstream_leaf_p_rule_tbl);
            } else {
                apply(elmo_downstream_leaf_s_rule_tbl) {
                    miss {
                        apply(elmo_downstream_leaf_default_p_rule_tbl);
                    }
                }
            }
        }
    }
}

action elmo_invalidate_leaf_p_rules_when_going_upstream_act() {
    remove_header(elmo_upstream_leaf_p_rule);
    modify_field(elmo_type.type_, 1);
}

action elmo_invalidate_leaf_p_rules_when_going_downstream_act() {
    remove_header(elmo_type);
    remove_header(elmo_upstream_leaf_p_rule);
    remove_header(elmo_upstream_spine_p_rule);
    remove_header(elmo_downstream_core_p_rule);
    remove_header(elmo_downstream_spine_head_p_rule);
    remove_header(elmo_downstream_spine_head_p_rule_last_id);
    remove_header(elmo_downstream_spine_last_p_rule);
    remove_header(elmo_downstream_spine_last_p_rule_last_id);
    remove_header(elmo_downstream_spine_default_bitmap);
    remove_header(elmo_downstream_leaf_head_p_rule);
    remove_header(elmo_downstream_leaf_head_p_rule_last_id);
    remove_header(elmo_downstream_leaf_last_p_rule);
    remove_header(elmo_downstream_leaf_last_p_rule_last_id);
    remove_header(elmo_downstream_leaf_default_bitmap);
}

table elmo_invalidate_leaf_p_rules_tbl { // popping p-rules based on egress port
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        elmo_invalidate_leaf_p_rules_when_going_upstream_act;
        elmo_invalidate_leaf_p_rules_when_going_downstream_act;
    }
    size : 4; // NUM_HOSTS_PER_LEAF + NUM_SPINES_PER_LEAF
}

control egress {
    if (valid(elmo_type)) {
        apply(elmo_invalidate_leaf_p_rules_tbl);
    }
}
