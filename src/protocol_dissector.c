/*
 *  @filename: protocol_dissector.c
 *  Author: zhaozhang@yxlink.com
 *  Date:  2015/11/10
 *  Support more than 200 portocols, such as
 * "MPEG","QuickTime","RealMedia","Windowsmedia","MMS","XBOX","QQ","SopCast","TVAnts"
 * "MOVE","RTSP","IMAPS","Icecast","PPLive","PPStream","Zattoo","SHOUTCast",etc...
 */

#include "protocol_dissector.h"

static u_int8_t nDPI_traceLevel = 0

static void debug_printf(u_int32_t protocol, void *id_struct,
			 ndpi_log_level_t log_level,
			 const char *format, ...) 
{
  va_list va_ap;
#ifndef WIN32
  struct tm result;
#endif

  if(log_level <= nDPI_traceLevel) {
    char buf[8192], out_buf[8192];
    char theDate[32];
    const char *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    if(log_level == NDPI_LOG_ERROR)
      extra_msg = "ERROR: ";
    else if(log_level == NDPI_LOG_TRACE)
      extra_msg = "TRACE: ";
    else
      extra_msg = "DEBUG: ";

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime,&result) );
    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    snprintf(out_buf, sizeof(out_buf), "%s %s%s", theDate, extra_msg, buf);
    SCLogInfo("debug_printf: %s", out_buf);
    fflush(stdout);
  }

  va_end(va_ap);
}

void init_ndpi_dissector(ThreadVars *tv)
{
    /* declare and initialise the detection module */
    NDPI_PROTOCOL_BITMASK all;

    // init global detection structure
    tv->ndpi_struct = ndpi_init_detection_module(detection_tick_resolution,
                                         malloc, free, debug_printf);
    if(tv->ndpi_struct == NULL) {
      SCLogError("init_ndpi_dissector ERROR: global structure initialization failed\n");
      exit(-1);
    }
    
    /*  enable all protocols */
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(tv->ndpi_struct, &all);

    // allocate memory for id and flow tracking
    size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
    size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

    if(_protoFilePath != NULL){
      ndpi_load_protocols_file(tv->ndpi_struct, _protoFilePath);
    }
    
}

struct ndpi_flow_struct *get_ndpi_flow(Packet *p)
{
    Flow *f = FlowGetFlowFromHash(p);
    if (f == NULL){
        return NULL;
    }
    if(f->ndpi_flow != NULL){
        return f->ndpi_flow;
    }
    
    return NULL;
}

unsigned int my_protocol_dissector(ThreadVars *tv, Packet *p, Flow *flow)
{  
    struct ndpi_id_struct *src, *dst;
    struct ndpi_flow_struct *ndpi_flow = NULL;
    u_int8_t proto;
    const struct ndpi_iphdr *iph;
	struct ndpi_ip6_hdr *iph6;
	u_int16_t ipsize;
    const u_int64_t time;
  
    // result only, not used for flow identification
    struct ndpi_protocol detected_protocol;

    if (flow->ndpi_flow){
        ndpi_flow = flow->ndpi_flow;
    }
    /* init pkt infor */
    proto = p->proto;
    iph = p->ip4h;
    iph6 = p->ip6h;
    ipsize = p->payload_len;
    src = flow->src;
    dst = flow->dst;
    time = flow->lastts_sec;
    
    if(flow->detection_completed || ndpi_flow == NULL) return(0);
    
    detected_protocol = ndpi_detection_process_packet(tv->ndpi_struct, ndpi_flow,
                                iph ? (uint8_t *)iph : (uint8_t *)iph6,
                                ipsize, time, src, dst);

    if(detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN){
        flow->detection_completed = 1;
    }

    if((detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) && (ndpi_flow->num_stun_udp_pkts > 0)){
        ndpi_set_detected_protocol(tv->ndpi_struct, ndpi_flow, NDPI_PROTOCOL_STUN, NDPI_PROTOCOL_UNKNOWN);
    }

    flow->protocol_id = detected_protocol.protocol;
    SCLogInfo("1=>>>detect_protocol.master_protocol is : %d", detected_protocol.master_protocol);
    SCLogInfo("2=<<<detect_protocol.protocol is : %d", detected_protocol.protocol);
      
}

void terminateDetection(ThreadVars *tv) 
{
  /* destroy the detection module */
  ndpi_exit_detection_module(tv->ndpi_struct, free);
}

