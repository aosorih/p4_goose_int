#include <core.p4>
#include <v1model.p4>

#define ETHERTYPE_GOOSE 0x88B8
#define ETHERTYPE_TELEMETRY 0x88B9
#define REPORT_MIRROR_SESSION_ID 1
#define NORMAL_PACKET 0
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
const bit<48> DST_MAC_MIRROR = 0x5254009b95c8;
#define REGISTER_SIZE 4096
#define UNSEEN_PORT   0

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
    bit<8>   sqnum;
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

#define REPORT_HS 16  // bytes
header telemetry_t {
    bit<48> ingress_timestamp;
    bit<48> egress_timestamp;
    bit<32> flow_hash;

}

struct digest_data_t {
    bit<48> src_addr;
    bit<48> dst_addr;
    bit<8>  in_port;
    bit<16> appid;
    bit<8> stnum;
    bit<8> sqnum;
}

struct metadata {
    @field_list(1) 
    bit<48> ingress_time;
    bit<48> egress_time;
    bit<32> register_index;
    bit<16> current_port;
    bool    should_write;
    bool    should_drop;
    bit<8>  new_stnum;
    bool    should_send_digest;
    digest_data_t digest_data;
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

    register<bit<16>>(REGISTER_SIZE) flow_port_register;
    register<bit<8>>(REGISTER_SIZE) stnum_register;

    action process_and_validate_flow(bit<48> srcAddr, bit<48> dstAddr, bit<16> appid, bit<8> stnum) {
        bit<32> tmp_register_index;
        bit<16> stored_port;
        bit<16> tmp_current_port = (bit<16>)standard_metadata.ingress_port;
        bit<8> stored_stnum;

        // 1. Calcular el hash completo
        hash(tmp_register_index, HashAlgorithm.crc32, (bit<32>)0, {srcAddr, dstAddr, appid}, (bit<32>)REGISTER_SIZE);
        meta.register_index = tmp_register_index;
        meta.current_port   = tmp_current_port;
        meta.new_stnum      = stnum;

        // 3. Leer el puerto guardado para este hash
        flow_port_register.read(stored_port, meta.register_index);
        stnum_register.read(stored_stnum, meta.register_index);

        meta.should_write = false;
        meta.should_drop  = false;
        meta.should_send_digest = false;

        // 4. Decidir 0==0, flujo nuevo
        if (stored_port == UNSEEN_PORT) {
            // --- Flujo Nuevo ---
            // Es la primera vez que vemos este hash.
            // Guardamos el puerto actual. Aseguramos que el puerto actual no sea 0.
            if (meta.current_port != UNSEEN_PORT) {
                meta.should_write = true;
            }
            // Dejamos pasar el paquete (acción por defecto).
        } else {
            // --- Flujo Existente ---
            // Ya hemos visto este hash. Comparamos los puertos.
            if (stored_port != meta.current_port) {
                // ¡Mismo flujo, puerto diferente! -> Suplantación
                // Marcamos para descarte (drop).
                meta.should_drop = true;
            }
        }

        if (stored_stnum != meta.new_stnum) {
            // stnum cambió! Marcar para enviar digest y actualizar stnum.
            meta.should_send_digest = true;
        }
    }

    action send_digest() {
        meta.digest_data.src_addr = hdr.ethernet.srcAddr;
        meta.digest_data.dst_addr = hdr.ethernet.dstAddr;
        meta.digest_data.in_port = (bit<8>)standard_metadata.ingress_port;
        meta.digest_data.appid = hdr.goose.appid; 
        meta.digest_data.stnum = hdr.goose.stnum;
        meta.digest_data.sqnum = hdr.goose.sqnum;
	    digest(1, meta.digest_data);
    }

    action action_update_stnum() {
        // Esta acción sólo escribe el stnum guardado en metadatos
        stnum_register.write(meta.register_index, meta.new_stnum);
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

     action drop() {
        mark_to_drop(standard_metadata);
    }

    action action_do_write() {
        // Esta acción SÓLO escribe. Se llama cuando should_write es true.
        flow_port_register.write(meta.register_index, meta.current_port);
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
        if (hdr.ethernet.etherType == ETHERTYPE_GOOSE && hdr.goose.isValid()) {
            process_and_validate_flow(hdr.ethernet.srcAddr, hdr.ethernet.dstAddr, hdr.goose.appid, hdr.goose.stnum);
            if (meta.should_drop) {
                drop();
            } else {
                if (meta.should_write) {
                    action_do_write();
                    mac_forwarding_table.apply();
                }
            }

            if (meta.should_send_digest) {
                send_digest(); // Enviar notificación al controlador
                action_update_stnum();   // Actualizar el registro con el nuevo stnum
            }
            
        }
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
            hdr.telemetry.flow_hash = meta.register_index;
            log_msg("TELEMETRY: time_ingress: {}, time_egress: {}, FlowID: {}", {meta.ingress_time, standard_metadata.egress_global_timestamp, meta.register_index});
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