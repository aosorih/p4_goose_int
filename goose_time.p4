#include <core.p4>
#include <v1model.p4>

#define ETHERTYPE_GOOSE 0x88B8
#define ETHERTYPE_TELEMETRY 0x88B9
#define REPORT_MIRROR_SESSION_ID 1
#define NORMAL_PACKET 0
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
const bit<48> DST_MAC_MIRROR = 0x5254009b95c8;

#define ETHERNET_HS 14  // bytes
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header goose_t {
    bit<16>  appid;
    bit<16>  lenght;
    bit<16>  reserved1;
    bit<16>  reserved2;
    bit<32>  hueco1;
    bit<256> gocbref;
    bit<16>  hueco2;
    bit<16>  timeallowedtolive;
    bit<16>  hueco3;
    bit<208> dataset;
    bit<16>  hueco4;    
    bit<96>  goid;
    bit<16>  hueco5;    
    bit<64>  t;
    bit<16>  hueco6;     
    bit<8>   stnum;
    bit<16>  hueco7;     
    bit<8>  sqnum;
    bit<16>  hueco8;     
    bit<8>   simulation;
    bit<16>  hueco9;    
    bit<8>   confrev;
    bit<16>  hueco10;    
    bit<8>   ndscom;
    bit<16>  hueco11;    
    bit<8>   numdatasetentries;
    bit<16>  hueco12;    
}

#define REPORT_HS 12  // bytes
header telemetry_t {
    bit<48> ingress_timestamp;
    bit<48> egress_timestamp;
}

struct metadata {
    @field_list(1)
    bit<48> ingress_time;
    bit<48> egress_time;
}

struct headers {
    ethernet_t ethernet;
    goose_t    goose;
    telemetry_t telemetry;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    meta
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_GOOSE: parse_goose;
            default: accept;
        }
    }
    
    state parse_goose {
        packet.extract(hdr.goose);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }
    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action add_telemetry_data() {
        meta.ingress_time = standard_metadata.ingress_global_timestamp;
    }
    
    table mac_forwarding_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop;
    }
    
    table goose_traffic_table {
        key = {
            hdr.ethernet.etherType: exact;
        }
        actions = {
            add_telemetry_data;
            NoAction;
        }
        size = 2;
        default_action = NoAction;
    }
    
    apply {
        mac_forwarding_table.apply();
	    goose_traffic_table.apply();
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE) {
            hdr.goose.setInvalid();
            hdr.telemetry.setValid();
	        hdr.ethernet.etherType = ETHERTYPE_TELEMETRY;
            hdr.ethernet.dstAddr = DST_MAC_MIRROR;
            hdr.telemetry.ingress_timestamp = meta.ingress_time;
            hdr.telemetry.egress_timestamp = standard_metadata.egress_global_timestamp;
	        log_msg("TELEMETRY: time_ingress: {} time_egress: {}", {meta.ingress_time, standard_metadata.egress_global_timestamp});
            truncate(ETHERNET_HS + REPORT_HS);
        } else {
            clone_preserving_field_list(CloneType.E2E, REPORT_MIRROR_SESSION_ID, 1);
            hdr.telemetry.setInvalid();
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.goose);
        packet.emit(hdr.telemetry);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    DeparserImpl()
) main;