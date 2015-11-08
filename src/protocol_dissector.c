#include "ndpi_main.h"
#include "decode.h"
#include "flow.h"

static u_int32_t size_id_struct = 0;		// ID tracking structure size
static u_int32_t size_flow_struct = 0;
static u_int32_t detection_tick_resolution = 1000;
static char *_protoFilePath   = NULL; /**< Protocol file path  */


static void init_ndpi_dissector(DetectEngineCtx *de_ctx)
{

    NDPI_PROTOCOL_BITMASK all;

    // init global detection structure
    de_ctx->ndpi_struct = ndpi_init_detection_module(detection_tick_resolution,
                                         malloc_wrapper, free_wrapper, debug_printf);
    if(de_ctx->ndpi_struct == NULL) {
      SCLogError("ERROR: global structure initialization failed\n");
      exit(-1);
    }

    // enable all protocols
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(de_ctx->ndpi_struct, &all);

    // allocate memory for id and flow tracking
    size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
    size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

    if(_protoFilePath != NULL){
      ndpi_load_protocols_file(de_ctx->ndpi_struct, _protoFilePath);
    }
    
}

static struct ndpi_flow_struct *get_ndpi_flow(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p)
{
    Flow *f = FlowGetFlowFromHash(tv, dtv, p);
    if (f == NULL){
        return NULL;
    }
        

}

static unsigned int my_protocol_dissector(DetectEngineCtx *de_ctx, ThreadVars *tv, DecodeThreadVars *dtv, Packet *p)
{  
    struct ndpi_id_struct *src, *dst;
    struct ndpi_flow_struct *ndpi_flow = NULL;
    u_int8_t proto;
    const struct ndpi_iphdr *iph;
	struct ndpi_ip6_hdr *iph6;
	u_int16_t ipsize;
    const u_int64_t time;
    // result only, not used for flow identification
    ndpi_protocol detected_protocol;

    ndpi_flow = get_ndpi_flow(tv, dtv, p);
    
    if(flow->detection_completed) return(0);
    
    detected_protocol = ndpi_detection_process_packet(de_ctx->ndpi_struct, ndpi_flow,
                                iph ? (uint8_t *)iph : (uint8_t *)iph6,
                                ipsize, time, src, dst);

    if(detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN){
        flow->detection_completed = 1;
    }

    if((detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) && (ndpi_flow->num_stun_udp_pkts > 0)){
        ndpi_set_detected_protocol(de_ctx->ndpi_struct, ndpi_flow, NDPI_PROTOCOL_STUN, NDPI_PROTOCOL_UNKNOWN);
    }
      

}


