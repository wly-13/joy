#include <stdlib.h>  
#include <errno.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

#include "p2f.h"

/*******************************************************************
 *******************************************************************
 * BEGIN Timer & Benchmark functions and struct
 *******************************************************************
 *******************************************************************
 */
#define MAX_FILE_LINE_LEN           (1024)
#define SIXTH_POWER                 (1000000)
#define TIME_ARRAY_SIZE             (49)

static uint64_t time_align;
static uint64_t stamp_num;

typedef enum proto_type {
    TYPE_TCP,
    TYPE_UDP,
    TYPE_TLS,
    TYPE_HTTP,
    TYPE_DNS,
    TYPE_UNKNOW,
    MAX_PROTO_TYPE,
} proto_type_e;

typedef struct proto_info_t {
    proto_type_e type;
    uint32_t flows;
    uint32_t packets;
    uint64_t bytes;
    uint64_t feature_extraction_tsc;
    uint64_t prediction_tsc;
} proto_info_t;

typedef struct joy_benchmark_t {
    uint64_t total_flow_count;
    uint64_t total_packet_count;
    uint64_t total_byte_count;
    uint64_t total_process_tsc;
    uint64_t feature_extraction_tsc;
    uint64_t prediction_tsc;
    uint64_t flow_table_tsc;
    uint64_t add_del_tsc;
    uint64_t fetch_pcap_tsc;
    uint64_t json_string_output_tsc;
    uint64_t flow_aging_complete_tsc;
    uint64_t flow_clean_tsc;
    proto_info_t proto_info[MAX_PROTO_TYPE];
} joy_benchmark_t;

typedef struct flow_info_t {
    proto_type_e type;
    uint32_t packets;
    uint64_t bytes;
    uint64_t feature_extraction_tsc;
    uint64_t prediction_tsc;
    uint64_t flow_aging_complete_tsc;
    int complete_flag;
} flow_info_t;

void update_flow_info(flow_record_t *ff, flow_info_t *f);
int time_compare(const void *a, const void *b);
int proto_compare(const void *a, const void *b);
void update_statistics(joy_benchmark_t *joy_benchmark, flow_info_t *f);
const char *proto2str(proto_type_e e);

#define TIME_CONVERSION_N(start, end, n)    ({        \
    ((end.tv_sec - start.tv_sec) * SIXTH_POWER +      \
    (end.tv_usec - start.tv_usec) - n * time_align);  \
})

#define TIME_CONVERSION(start, end)                   \
    TIME_CONVERSION_N(start, end, 1)

#define TIME_START(name)                              \
    struct timeval name##_s;                          \
    struct timeval name##_e;                          \
    gettimeofday(&name##_s, NULL);

#define TIME_END_N(name, data, n)                     \
    gettimeofday(&name##_e, NULL);                    \
    data += TIME_CONVERSION_N(name##_s, name##_e, n); \
    stamp_num += (2 * n);

#define TIME_END(name, data)                          \
    TIME_END_N(name, data, 1)

#define TIME_ALIGN    ({                                                    \
    int n = 0;                                                              \
    uint64_t time_array[TIME_ARRAY_SIZE] = {0};                             \
    struct timeval align_s;                                                 \
    struct timeval align_e;                                                 \
    for (n = 0; n < TIME_ARRAY_SIZE; n++) {                                 \
        gettimeofday(&align_s, NULL);                                       \
        gettimeofday(&align_e, NULL);                                       \
        time_array[n] = (align_e.tv_sec - align_s.tv_sec) * SIXTH_POWER +   \
            (align_e.tv_usec - align_s.tv_usec);                            \
    }                                                                       \
    qsort(time_array, TIME_ARRAY_SIZE, sizeof(uint64_t), time_compare);     \
    time_align = time_array[TIME_ARRAY_SIZE / 2];                           \
})

/*******************************************************************
 *******************************************************************
 * END Timer & Benchmark mcros and struct
 *******************************************************************
 *******************************************************************
 */