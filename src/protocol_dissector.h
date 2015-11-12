/*
 *  @filename: protocol_dissector.h
 *  Author: zhaozhang@yxlink.com
 *  Date:  2015/11/10
 *  Support more than 200 portocols, such as
 * "MPEG","QuickTime","RealMedia","Windowsmedia","MMS","XBOX","QQ","SopCast","TVAnts"
 * "MOVE","RTSP","IMAPS","Icecast","PPLive","PPStream","Zattoo","SHOUTCast",etc...
 */

#ifndef __PROTOCOL_DISSECTOT_H__
#define __PROTOCOL_DISSECTOT_H__

#include "ndpi_main.h"
#include "threadvars.h"
#include "decode.h"
#include "flow.h"


static u_int32_t size_id_struct = 0;		// ID tracking structure size
static u_int32_t size_flow_struct = 0;
static u_int32_t detection_tick_resolution = 1000;
static char *_protoFilePath   = NULL; /**< Protocol file path  */

void init_ndpi_dissector(ThreadVars *tv);
static struct ndpi_flow_struct *get_ndpi_flow(Packet *p);
unsigned int my_protocol_dissector(ThreadVars *tv, Packet *p, Flow *flow);
void terminateDetection(ThreadVars *tv);


#endif
 

