// (C) 2006 Camilo Viecco.  All rights reserved.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
//
// Author: Camilo Viecco



#ifndef ELEMENT_HPP
#define ELEMENT_HPP

#include <pcap.h>


#define MAX_ANNOT_PER_ELEMENT 14 
#define MAX_PACKET_PAYLOAD_LENGTH 3000
#define MAX_ANNOT_PER_FLOW 4

//////define the element types
#define TAGGED_PACKET 0
#define TAGGED_FLOW   1

//define annotation tags
#define FLOW_ANNOT_LAST_EMIT_SEC 1
#define FLOW_ANNOT_DB_ID         2
#define FLOW_ANNOT_CLASS_ID      3  
#define FLOW_ANNOT_MARKER_FLAGS  4
#define FLOW_ANNOT_MARKER_STATE  5
#define FLOW_ANNOT_PERF_STATE    6
#define FLOW_ANNOT_ENTRO_STATE   7
#define FLOW_ANNOT_ENTRO_STATE1  8
#define FLOW_ANNOT_PACK_DIR_HIST 9
#define FLOW_ANNOT_LAST_PACK_C   10
#define FLOW_ANNOT_LAST_BYTE_C   11
#define FLOW_ANNOT_SIG_PACK_SIZE 12
#define PACKET_ANNOT_BIDIR_FLOW  1
#define PACKET_ANNOT_IFACE_ID    2
#define PACKET_ANNOT_LIMIT_OUT   3
#define PACKET_ANNOT_PACK_DIR    4

//define the packet tag types
#define PACKET_TAG_BIDIR_FLOW  1
#define PACKET_TAG_UNIDIR_FLOW 2
#define PACKET_TAG_DIR_FORWARD 0
#define PACKET_TAG_DIR_REVERSE 1

//define the flow tag types
#define FLOW_TAG_BIDIRECTIONAL  1
#define FLOW_TAG_UNIDIRECTIONAL 2
#define FLOW_TAG_WITH_OS        4
#define FLOW_TAG_WITH_PROTOCOL  8
#define FLOW_TAG_WITH_DB_ID    16

//define the overflow flow tags
#define FLOW_SRC_BYTES_OVERFLOW 1
#define FLOW_DST_BYTES_OVERFLOW 2
#define ICMP_FROM_SRC_OVERFLOW  4
#define ICMP_FROM_DST_OVERFLOW  8

//define the icmp marker flags
#define FLOW_ICMP_DST_UNREACH_NET_UNREACH  0x00001 /*code 0*/
#define FLOW_ICMP_DST_UNREACH_HOST_UNREACH 0x00002 /*code 1*/
#define FLOW_ICMP_DST_UNREACH_PROT_UNREACH 0x00004 /*code 2*/
#define FLOW_ICMP_DST_UNREACH_PORT_UNREACH 0x00008 /*code 3*/
#define FLOW_ICMP_DST_UNREACH_FRAG         0x00010 /*code 4*/
#define FLOW_ICMP_DST_UNREACH_SOURCE_ROUTE 0x00020 /*code 5*/
#define FLOW_ICMP_DST_UNREACH_UNKOWN       0x00040 /*code 6 7*/
#define FLOW_ICMP_DST_UNREACH_ISOLATED     0x00080 /*code 8*/
#define FLOW_ICMP_DST_UNREACH_ADMIN_PROHIB 0x00100  /*codes 9,10,13*/
#define FLOW_ICMP_DST_UNREACH_SERVICE_TYPE 0x00200  /*codes 11,12*/
#define FLOW_ICMP_DST_UNREACH_OTHER        0x00400  /*codes 14,15*/
#define FLOW_ICMP_SOURCE_QUENCH            0x00800  
#define FLOW_ICMP_REDIRECT                 0x01000
#define FLOW_ICMP_ALTERNATE_ADDR           0x02000
#define FLOW_ICMP_TIME_EXCEEDED            0x04000
#define FLOW_ICMP_PARAMETER_PROBLEM        0x08000
#define FLOW_ICMP_0THER                    0x08000

//define flow tags
#define FLOW_MARKER_DONE_PROCESS 0xFFFFFFFF
#define FLOW_MARKER_DONE_TAG     0xF0000000

#define debug(x...)   fprintf(stderr,x)
#define fatal(x...)   do { debug("[-] ERROR: " x); exit(1); } while (0)

//-----------define portable, pcap structs
struct portable_timeval{
   uint32_t tv_sec;
   uint32_t tv_usec;
};

struct portable_pcap_packet_hdr{
        struct portable_timeval ts  __attribute__((packed));   // time stamp
        uint32_t caplen         __attribute__((packed));   //length of portion present
        uint32_t len            __attribute__((packed));   // length this packet (off wire)
};



using namespace std;

typedef union Element_Annotation_Tag{
     void  *as_ptr;
     uint32_t as_int32;
     uint64_t as_int64;
      }Element_Annotation;

class Tagged_Element{
  public:
   int empty_class;
   Element_Annotation annot[MAX_ANNOT_PER_ELEMENT];
   Tagged_Element();
};
 Tagged_Element:: Tagged_Element(){
   empty_class=0;
   memset(annot,0x00,sizeof(Element_Annotation)*MAX_ANNOT_PER_ELEMENT);
}


class Tagged_Packet: public Tagged_Element{
  private:
    int packet_type;
    int process_flags;
  public:
    struct pcap_pkthdr *pcap_hdr;
    u_char* data;
    int get_packet_type(){return packet_type;};
};

class Tagged_IP_Packet: public Tagged_Packet{
   public:
    int ip_header_offset;
    int transport_offset;
    int payload_offset;
};

typedef struct tcp_stats_tag{
    unsigned int last_ack;
    unsigned int last_seq;
    unsigned short last_window;
    unsigned short non_inc_seq;
    unsigned short non_inc_ack;
    unsigned short out_of_window_ack;
    unsigned short out_of_window_seq;
    unsigned char tcp_flags;    
}Tcp_Stats;

typedef union l4_stats_tag{
    Tcp_Stats tcp;
    int other;
}L4_Stats;


typedef struct Flow_Stats_tag{
    unsigned int packets;
    unsigned int bytes;
    unsigned int start_time;
    unsigned int end_time;
    unsigned short end_msec;
    unsigned short start_msec;
    unsigned char ip_flags;
    unsigned char tcp_flags;
    unsigned short icmp_seen;                /* icmp_seen_flags */
    unsigned short icmp_packets;             /* icmp_packet_count */
    L4_Stats l4;
}Flow_Stats;


class Bidir_Flow_Stats{
  public:
    Flow_Stats src;
    Flow_Stats dst;  
     //bidirectional stats accessed via methods.
    unsigned int packets() const {return src.packets+dst.packets;};
    unsigned int bytes() const {return src.bytes+dst.bytes;}
    unsigned int start_time() const {if (src.start_time<dst.start_time)
                                    return src.start_time; else return dst.start_time; }
    unsigned int end_time(){if (src.end_time>dst.end_time)
                                    return src.end_time; else return dst.end_time; }
    unsigned short start_msec(){if ((src.start_time<dst.start_time) ||
                                    (src.start_time==dst.start_time && src.start_msec<dst.start_msec))
                                    return src.start_msec; else return dst.start_msec; }
    unsigned short end_msec(){if ((src.end_time>dst.end_time) ||
                                    (src.end_time==dst.end_time && src.end_msec>dst.end_msec))
                                    return src.end_msec; else return dst.end_msec; }
    unsigned char  ip_flags() {return (src.ip_flags  | dst.ip_flags);};
    unsigned char  tcp_flags(){return (src.tcp_flags | dst.tcp_flags);};
    unsigned short icmp_seen(){return (src.icmp_seen | dst.icmp_seen);};
    unsigned char  icmp_packets(){return src.icmp_packets+dst.icmp_packets;};

};

class Flow_Annot{
   public:
      virtual ~Flow_Annot();
};

class Tagged_IPV4_Flow: public Tagged_Element{
  public:
    unsigned int source_ip;
    unsigned int dest_ip; 
    u_char protocol;
    unsigned short src_port;
    unsigned short dst_port;
    Bidir_Flow_Stats stats;
    //Flow_Annot *fannot[MAX_ANNOT_PER_FLOW]; 
};

class Processing_Block{
  public:
    static bool live_read;
    volatile static bool dbi_initialized;
    static bool terminate;
    static int setuid;
    Processing_Block **next_stage;
    bool initialized;
    int num_outputs;
    int valid_outputs;
  public:
    virtual int entry_point(const Tagged_Element *inpacket){return -1;};
    int entry_point(Tagged_Element *in_packet,int entry_id);
    int get_valid_input_for_entry(int entry_id);
    int get_numoutputs();
    int initialize(int num_outs){return -1;};
    int set_output_point(Processing_Block *out_block,int out_index);
    virtual ~Processing_Block(){};
};

//////implementations
bool Processing_Block::live_read=false; // can this go here?
volatile bool Processing_Block::dbi_initialized=false;
bool Processing_Block::terminate=false;
int  Processing_Block::setuid=-1;

class Packet_Processing_Block{
   int trash;
};

class Null_Processing_Block : public Processing_Block{
    virtual int entry_point(const Tagged_Element *inpacket){return 0;};
};

////////////implementations


#endif












