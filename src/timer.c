#include "timer.h"

void update_flow_info(flow_record_t *ff, flow_info_t *f)
{
    /* update protocol type, L7 first */
    if (ff->twin != NULL){
        f->bytes = ff->num_bytes + ff->twin->num_bytes;
        f->packets = ff->np + ff->twin->np;
        ff->flow_info_processed = 1;
        ff->twin->flow_info_processed = 1;
    } else {
        f->bytes = ff->num_bytes;
        f->packets = ff->np;
        ff->flow_info_processed = 1;
    }
    

    if (ff->key.prot == IPPROTO_TCP) {
        f->type = TYPE_TCP;
    } else if (ff->key.prot == IPPROTO_UDP) {
        f->type = TYPE_UDP;
    } else {
        f->type = TYPE_UNKNOW;
    }

    if (ff->tls && ff->tls->role) {
        f->type = TYPE_TLS;
        return;
    }
    if (ff->dns && ff->dns->pkt_count) {
        f->type = TYPE_DNS;
        return;
    }
    if (ff->http && ff->http->num_messages) {
        f->type = TYPE_HTTP;
        return;
    }

}

#define PROTO_INFO_UPDATE(F, JOY_BENCHMARK)                                   \
    JOY_BENCHMARK->proto_info[f->type].flows++;                               \
    JOY_BENCHMARK->proto_info[f->type].packets += F->packets;                 \
    JOY_BENCHMARK->proto_info[f->type].bytes += F->bytes;

void update_statistics(joy_benchmark_t *joy_benchmark, flow_info_t *f) {

    PROTO_INFO_UPDATE(f, joy_benchmark);

    joy_benchmark->total_flow_count++;
    joy_benchmark->total_packet_count += f->packets;
    joy_benchmark->total_byte_count += f->bytes;
}

const char *proto2str(proto_type_e e) {
    switch (e) {
        case TYPE_TCP:
            return "TCP";
        case TYPE_UDP:
            return "UDP";
        case TYPE_TLS:
            return "TLS";
        case TYPE_HTTP:
            return "HTTP";
        case TYPE_DNS:
            return "DNS";
        default:
            return NULL;
    }
}

int time_compare(const void *a, const void *b) {
    return *(uint64_t *)a - *(uint64_t *)b;
}

int proto_compare(const void *a, const void *b) {
    return ((proto_info_t *)b)->flows -
           ((proto_info_t *)a)->flows;
}
