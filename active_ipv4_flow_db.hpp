// (C) 2006 The Trustees of Indiana University.  All rights reserved.
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

#ifndef ACTIVE_FLOW_DB_HPP
#define ACTIVE_FLOW_DB_HPP


#include "element.h"
//enums:
#include <netinet/in.h>

//structs
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>


#include <list>
#include <map>
#include <algorithm>

#include <iostream>

using namespace std;


/////////////Define classes
class Flow_helpers{
  public:
    static int packet_to_ipv4_flows( Tagged_IP_Packet *inpacket,
                                               Tagged_IPV4_Flow *forward,
                                               Tagged_IPV4_Flow *revese ,
                                               Tagged_IPV4_Flow *side_effected,
                                               const bool  do_recurse);
    static int make_reverse(Tagged_IPV4_Flow *source,Tagged_IPV4_Flow *dest);
    static unsigned int get_flags(const struct icmphdr * inheader);
    static int flow_stats_update(Flow_Stats *target, const Flow_Stats *source);
    static int print_flow (Tagged_IPV4_Flow *in_flow);
    static int print_flow_stats (Flow_Stats *in_stats);
    static int print_ipv4_addr(unsigned int ip);
    static int update_l4_stats(const struct Tagged_IP_Packet *inpacket,  Flow_Stats *src_stats ,Flow_Stats *dst_stats);
    inline static bool mod_between(unsigned int a, unsigned int delta, unsigned int b){
                     if ( a<(a+delta))
                          return ((a<b) && (b<a+delta));
                     else
                         return !(a+delta<b && b<a);  
    }     
};



class Active_flow_indexer{
  public:
    unsigned int source_ip;
    unsigned int dest_ip;
    u_char protocol;
    unsigned short src_port;
    unsigned short dst_port;
    Active_flow_indexer(){source_ip=0;};
 public:
   inline int create_from_flow(const Tagged_IPV4_Flow *flow){
      source_ip=flow->source_ip;
      dest_ip=flow->dest_ip;
      protocol=flow->protocol;
      src_port=flow->src_port;
      dst_port=flow->dst_port;
      return 0;
   };
   inline int flow_from_index(Tagged_IPV4_Flow *flow){
      flow->source_ip=source_ip;
      flow->dest_ip=dest_ip;
      flow->protocol=protocol;
      flow->src_port=src_port;
      flow->dst_port=dst_port;
      memset(&(flow->stats.src),0x00,sizeof(Flow_Stats));
      flow->stats.src.start_time=0-1;
      flow->stats.dst=flow->stats.src;
      memset(&(flow->annot),0x00,MAX_ANNOT_PER_ELEMENT*sizeof(Element_Annotation));
      return 0;
   };

   inline bool equal_to_flow(const Tagged_IPV4_Flow *flow){
      return ( (flow->source_ip ==source_ip) &&
               (flow->dest_ip   ==dest_ip) &&
               (flow->protocol  ==protocol) &&
               (flow->src_port  ==src_port)    &&
               (flow->dst_port  ==dst_port));
   }
   int print(){
      Flow_helpers::print_ipv4_addr(source_ip);
      cout << "\t";
      Flow_helpers::print_ipv4_addr(dest_ip);
      cout << " \t";
      cout << (int)protocol <<" " << src_port <<" " << dst_port <<" ";
      return 0;
   }
    
};

class Flow_db_Tags{
   unsigned int last_update_sec;
   unsigned int last_packet_count;
};

class Bidir_active_flow_db{
 public:
  map<Active_flow_indexer,list<Tagged_IPV4_Flow>::iterator> index;
 public:
  list<Tagged_IPV4_Flow> data_rep;
  list<Flow_db_Tags> tag_list;
 public:
  int update_db_with(Tagged_IP_Packet *inpacket);
  int update_db_with(Tagged_IPV4_Flow *);
};

///////////////////////////////////////////////////////////////////////////
//
//     now implementation, almost as same order as above, first start with opertators
//
////////////////////////////////////////////////////////////////////////////////

inline   bool operator < (const Active_flow_indexer &lhs,const Active_flow_indexer &rhs){


#define USE_64_BIT_COMPS

#ifndef USE_64_BIT_COMPS

       if(lhs.source_ip!=rhs.source_ip)
           return lhs.source_ip<rhs.source_ip;
       else{
          if (lhs.dest_ip!=rhs.dest_ip)
             return lhs.dest_ip<rhs.dest_ip;
          else{
             if(lhs.src_port!=rhs.src_port)
                return lhs.src_port<rhs.src_port;
             else{
                if(lhs.dst_port!=rhs.dst_port)
                   return lhs.dst_port<rhs.dst_port;
                else
                   return lhs.protocol<rhs.protocol;
             } 
          }
       }
       
#else
   uint64_t left,right;
   left = (uint64_t) lhs.source_ip  <<32 | lhs.dest_ip;
   right=  (uint64_t) rhs.source_ip <<32 | rhs.dest_ip;
   if(left!=right)
      return left<right;
   left  =  (uint64_t) lhs.src_port <<32 | (uint64_t)lhs.dst_port<<16 | lhs.protocol;
   right =  (uint64_t) rhs.src_port <<32 | (uint64_t)rhs.dst_port<<16 | rhs.protocol;
   return left<right;
#endif



   }
  bool operator == (const Active_flow_indexer &lhs,const Active_flow_indexer &rhs){
    return ((lhs.source_ip==rhs.source_ip) &&
            (lhs.dest_ip  ==rhs.dest_ip) &&
            (lhs.src_port ==rhs.src_port) &&
            (lhs.dst_port ==rhs.dst_port) &&
            (lhs.protocol ==rhs.protocol) 
           );
  }

//////////////////
static int validate_ip_and_transhdr_length(int offset_to_validate , u_char *pkt_data, unsigned int data_len  ){
   //return values:
   // -1 invalid
   // -2 ip version not understood
   //  number of extra valid ip+trans , for icmp recursion!
   struct ip      *ip_header;
   struct icmphdr *icmp_header;
   int rvalue;
   int offset;

   offset=offset_to_validate;
   if (data_len<offset+sizeof(struct ip)){
      return -1;
   }
   ip_header=(struct ip*)(pkt_data+offset_to_validate);   

   //check for version
   if (4==ip_header->ip_v){// only understand ipv4!!!!
       //check for ip header length
       if ((5<ip_header->ip_hl) || (data_len<ip_header->ip_hl*4+offset)){
           return -1;
       }
       offset=offset+ip_header->ip_hl*4;
       //now validate on the protocol type
       switch(ip_header->ip_p){
            case  IPPROTO_TCP:
                          //check length,break
                          if (data_len<offset+sizeof(struct tcphdr)){
                            return -1;
                          }
                          break;
            case  IPPROTO_UDP:
                          //check lenght, 
                          if (data_len<offset+sizeof(struct udphdr)){
                            return -1;
                          }
                          break;
            case  IPPROTO_ICMP:
                          //check length
                          if (data_len<offset+sizeof(struct icmphdr)){
                            return -1;
                          }
                          icmp_header=(struct icmphdr *)(pkt_data+offset);
                          offset=offset+sizeof(struct icmphdr);
			  //icmp_header=(struct icmphdr *)(pkt_data+offset);
                          // only do recursion based on rfc 792
                          switch(icmp_header->type){
				case ICMP_DEST_UNREACH:
                                case ICMP_SOURCE_QUENCH:
                                case ICMP_REDIRECT:
                                case ICMP_TIME_EXCEEDED:
                                case ICMP_PARAMETERPROB:
                                              offset=offset;
                                              rvalue=validate_ip_and_transhdr_length(offset,pkt_data,data_len);
                                              if(0>rvalue)
                                                 return 0;
                                              else{
                                              return rvalue+1;}
                                     break;
                                default:
                                    return 0;

                          }

                          break;
            default:
                 return 0;
                  
       }
   }
   else{
      //do other ip versions here.....
      return -2;
   }

   return 0;
    
}
///////////
int Flow_helpers::print_ipv4_addr(unsigned int ip){
  cout << ((ip & 0xFF000000) >> 24)  <<"."<< ((ip &  0xFF0000)>>16)  <<"." << ((ip & 0xFF00) >> 8) << "." << (ip & 0xFF) ;
  return 0;
}

////////
int Flow_helpers::print_flow_stats (Flow_Stats *in_stats){
   cout << in_stats->packets << " ";
   cout << in_stats->bytes << " ";
   cout << (int)in_stats->tcp_flags << " ";
   cout << (int)in_stats->icmp_packets << " ";
   cout << (int)in_stats->icmp_seen << " " ; 
   return 0;
}


////////////

int Flow_helpers::print_flow (Tagged_IPV4_Flow *in_flow){
   //cout << in_flow->source_ip <<" ";
   print_ipv4_addr(in_flow->source_ip);
   cout << "\t";
   //cout << in_flow->dest_ip <<" ";
   cout << "\t";
   print_ipv4_addr(in_flow->dest_ip);
   cout << " "<<(int)in_flow->protocol <<" "; 
   cout << in_flow->src_port <<" ";
   cout << in_flow->dst_port <<" ";

   print_flow_stats(&(in_flow->stats.src));
   print_flow_stats(&(in_flow->stats.dst));
    
   cout << endl;
   return 0;
}



////////
 int Flow_helpers::flow_stats_update(Flow_Stats *target, const Flow_Stats *source){
 
   //validation for bytes only
   target->bytes+=source->bytes;
   if(target->bytes<source->bytes){target->bytes=0-1;};

   target->packets+=source->packets;
   target->icmp_packets+=source->icmp_packets;

   target->tcp_flags|=source->tcp_flags;
   target->ip_flags|=source->tcp_flags;
   target->icmp_seen|=source->icmp_seen;

   //do times  
   if((target->start_time>source->start_time) ||
      ((target->start_time==source->start_time) && (target->start_msec>source->start_msec) ) )
      {
       //fprintf(stderr,"udating start_time source sec=%u\n",target->start_time);
       target->start_time=source->start_time; 
       target->start_msec=source->start_msec;
       };

   if((target->end_time<source->end_time) ||  
     ((target->end_time==source->end_time) && (target->end_msec<source->end_msec) ) )
      {target->end_time=source->end_time; target->end_msec=source->end_msec;};

    return 0;
}


////////////////
int Flow_helpers::make_reverse(Tagged_IPV4_Flow *source,Tagged_IPV4_Flow *dest){
   dest->source_ip=source->dest_ip;
   dest->dest_ip  =source->source_ip;
   dest->protocol =source->protocol;
   dest->src_port=source->dst_port;
   dest->dst_port=source->src_port;
   //dest->stats=source->stats;
   dest->stats.src=source->stats.dst;
   dest->stats.dst=source->stats.src;
   return 0;

}


////////////////////////
//This function could be MUCH better written, but again clarity above performance
//
unsigned int Flow_helpers::get_flags(const struct icmphdr *in_header){
  unsigned int rvalue=0;
  switch (in_header->type){
          case ICMP_DEST_UNREACH:
                     switch(in_header->code){
                            case ICMP_NET_UNREACH:            
                                    rvalue= FLOW_ICMP_DST_UNREACH_NET_UNREACH;
                                    break;  
                            case ICMP_HOST_UNREACH:             
                                    rvalue =FLOW_ICMP_DST_UNREACH_HOST_UNREACH;
                                    break;
                            case ICMP_PROT_UNREACH:
                                    rvalue =FLOW_ICMP_DST_UNREACH_PROT_UNREACH;
                                    break;           
                            case ICMP_PORT_UNREACH:
                                    rvalue=FLOW_ICMP_DST_UNREACH_PORT_UNREACH;
                                    break;
                            case ICMP_FRAG_NEEDED:
                                   rvalue =FLOW_ICMP_DST_UNREACH_FRAG;
                                   break;      
                            case ICMP_SR_FAILED:       
                                   rvalue=FLOW_ICMP_DST_UNREACH_SOURCE_ROUTE;
                                   break;
                            case  ICMP_NET_UNKNOWN:  //yes fallthrough   
                            case  ICMP_HOST_UNKNOWN:
                                   rvalue=FLOW_ICMP_DST_UNREACH_UNKOWN;
                                   break;       
                            case  ICMP_HOST_ISOLATED:
                                   rvalue=FLOW_ICMP_DST_UNREACH_ISOLATED;
                                   break;     
                            case ICMP_NET_ANO:    //again fallthrough       
                            case ICMP_HOST_ANO:
                                   rvalue=FLOW_ICMP_DST_UNREACH_ADMIN_PROHIB;
                                   break;        
                            case ICMP_NET_UNR_TOS:  
                            case ICMP_HOST_UNR_TOS:  
                                   rvalue=FLOW_ICMP_DST_UNREACH_SERVICE_TYPE;
                                   break;
                            case ICMP_PKT_FILTERED:      
                                   rvalue=FLOW_ICMP_DST_UNREACH_ADMIN_PROHIB;
                                   break;
                            default:
                                 rvalue =FLOW_ICMP_DST_UNREACH_OTHER;
                     }
                     break;
          case ICMP_SOURCE_QUENCH:
              rvalue=FLOW_ICMP_SOURCE_QUENCH;
              break;   
          case ICMP_REDIRECT:
              rvalue=FLOW_ICMP_REDIRECT;
              break;
          case ICMP_TIME_EXCEEDED:
              rvalue=FLOW_ICMP_TIME_EXCEEDED;
              break;
          case ICMP_PARAMETERPROB:
              rvalue=FLOW_ICMP_PARAMETER_PROBLEM;
              break;
          default:
              rvalue=FLOW_ICMP_0THER;
  }
  return rvalue;
}



////////////////////////////////////////////
/// This is one of the hardest functions
int Flow_helpers::packet_to_ipv4_flows( Tagged_IP_Packet *inpacket, 
                                               Tagged_IPV4_Flow *forward, 
                                               Tagged_IPV4_Flow *reverse ,
                                               Tagged_IPV4_Flow *side_effected,
                                               const bool  do_recurse){
   struct ip      *ip_header;
   struct tcphdr  *tcp_header;
   struct udphdr  *udp_header;
   struct icmphdr *icmp_header;
   int valid=0;
   int offset=inpacket->ip_header_offset;
   int in_offset=inpacket->ip_header_offset;
   Tagged_IPV4_Flow temp_trash;
   int rvalue=0;
   int i;

   //valiate lenght_and_ip type!!!!
   if(do_recurse){ 
     valid=validate_ip_and_transhdr_length(inpacket->ip_header_offset,inpacket->data,inpacket->pcap_hdr->caplen);
     if(valid<0){return valid;};
   }
  
   ip_header=(struct ip*)(inpacket->data+inpacket->ip_header_offset);   
   

   //assume the packet is on the revese path, this makes easier icmp tracking
   //We set the defaults here
   reverse->source_ip=ntohl(ip_header->ip_dst.s_addr);
   reverse->dest_ip  =ntohl(ip_header->ip_src.s_addr);
   reverse->protocol =ip_header->ip_p;
   reverse->src_port=0;
   reverse->dst_port=0;
   reverse->stats.src.start_time=inpacket->pcap_hdr->ts.tv_sec;
   reverse->stats.src.end_time=inpacket->pcap_hdr->ts.tv_sec;
   reverse->stats.src.start_msec=inpacket->pcap_hdr->ts.tv_usec/1000;
   reverse->stats.src.end_msec=inpacket->pcap_hdr->ts.tv_usec/1000;
   reverse->stats.src.packets=0;
   reverse->stats.src.bytes=0;
   reverse->stats.src.tcp_flags=0;
   reverse->stats.src.ip_flags=0;
   reverse->stats.src.icmp_seen=0;
   reverse->stats.src.icmp_packets=0;
   reverse->stats.dst=reverse->stats.src;
   //actualy fix the times....
   reverse->stats.src.start_time=0xF0000000;//4000000000;
   reverse->stats.src.end_time=0;
   reverse->stats.src.start_msec=0;
   reverse->stats.src.end_msec=0;


   //empty the annot
   for(i=0;i<MAX_ANNOT_PER_ELEMENT;i++){
     reverse->annot[i].as_int64=0;
     forward->annot[i].as_int64=0;
   }

   offset=offset+ip_header->ip_hl*4;
   switch(ip_header->ip_p){
            //watch out.... i am using the fallthrough mechanism in switch....!!!!
            case  IPPROTO_TCP:
                          tcp_header=(struct tcphdr*)(inpacket->data +offset);
                          //anotate tcp flags .. ugly code
                          reverse->stats.dst.tcp_flags= ((u_char *) tcp_header)[13] & 0x3F ;
                          ///YES no 'break'!!
            case  IPPROTO_UDP:
                          udp_header=(struct udphdr *)(inpacket->data +offset);
                          reverse->src_port=ntohs(udp_header->dest);
                          reverse->dst_port=ntohs(udp_header->source);
                          //again NO break!!
            default:      //make forward here!!
                          reverse->stats.dst.packets=1;
                          reverse->stats.dst.bytes=ntohs(ip_header->ip_len)-ip_header->ip_hl*4;
                          //reverse->stats=reverse->dst_stats;
                          //flow_stats_update(reverse.stat,reverse.dst_stat);
                          make_reverse(reverse,forward);
                          break;
            case  IPPROTO_ICMP:
                          icmp_header=(struct icmphdr*)(inpacket->data +offset);
                          

                          //make the forward by making a BAD reverse
                          reverse->src_port=icmp_header->code;
                          reverse->dst_port=icmp_header->type;
                          
                          //assume reverse, make forward, which will revese the above
                          make_reverse(reverse,forward);
                          
                          //now fix reverse according to type
                          switch(icmp_header->type){
                                case ICMP_DEST_UNREACH:
                                case ICMP_SOURCE_QUENCH:
                                case ICMP_REDIRECT:
                                case ICMP_TIME_EXCEEDED:
                                case ICMP_PARAMETERPROB:
                                         //put flags in forward
                                         forward->stats.src.icmp_seen=get_flags(icmp_header);
                                         //forward->stats.icmp_seen=forward->src_stats.icmp_seen;
                                         //the reverse in on the payload.. first verify we got enough info!!
                                         //then recurse on a "modified offset"
                                         //restore the real offset
                                         if((valid>0) && do_recurse){
                                               //there is enough data...
                                               //modify inoffset
                                               inpacket->ip_header_offset=offset+sizeof(struct icmphdr);

                                               packet_to_ipv4_flows(inpacket,reverse,&temp_trash ,&temp_trash,false);
                                               //restore offset
                                               inpacket->ip_header_offset=in_offset;

                                               //now, if the reverse does not matches the forward then we need to create
                                               //the side effect!!!
                                               if((reverse->source_ip!=forward->dest_ip) || (reverse->dest_ip!=forward->source_ip)){
                                                    //we have a side effect....
                                                    // the reverse is really the side effect!
                                                    *side_effected=*reverse;
                                                    rvalue=1;
                                                    //lets think what else is there..this occurs when:
                                                    //   a. we get an icmp message from a rounter
                                                    //   b. somebody that cannot remove our message is trying to mess things up
                                                    //   we should treat the forward as the packet source!!
                                                    //   and the reverse as an icmp related view... 
                                                    //
                                                    // second tought.. whould this mess up the recursion?
                                                    reverse->stats.dst.bytes=ntohs(ip_header->ip_len)-(ip_header->ip_hl*4)
                                                                             -sizeof(struct icmphdr); //still bad.. more needs to be removed
                                                    reverse->stats.dst.icmp_seen=forward->stats.src.icmp_seen;
                                                    reverse->stats.dst.icmp_packets=1;           
                                                    reverse->stats.src.packets=0;
                                                    reverse->stats.src.bytes=0;

                                                    forward->stats.src.icmp_packets=1;  //or packets??
                                                    forward->stats.src.bytes=reverse->stats.dst.bytes;
                                                    *side_effected=*reverse;

                                               }else{
                                                   //put fix reverse bytes, flags etc
                                                   reverse->stats.dst.bytes=ntohs(ip_header->ip_len)-(ip_header->ip_hl*4);
                                                   reverse->stats.dst.icmp_seen=forward->stats.src.icmp_seen;
                                                   reverse->stats.dst.icmp_packets=1;
                                                   reverse->stats.src.packets=0;
                                                   reverse->stats.src.bytes=0; 
                                                   //fix forward too
                                                   forward->stats.src.packets=1;
                                                   forward->stats.src.bytes=reverse->stats.dst.bytes;
                                               }
                                         }
                                         else{
                                            reverse->src_port=icmp_header->type;
                                            reverse->dst_port=icmp_header->code;
                                         }
                                         break;

                                default: //all other icmp types
                                         //fix type (on reverse), fix values for stats;
                                         forward->stats.src.packets=1;
                                         forward->stats.src.bytes=ntohs(ip_header->ip_len)-(ip_header->ip_hl*4+0);
                                         //forward->stats=forward->src_stats;
                                         //reverse->stats=forward->src_stats;
                                         reverse->stats.dst=forward->stats.src;

                                         switch(icmp_header->type){
                                               case ICMP_ECHOREPLY:
                                                    reverse->src_port=ICMP_ECHO;
                                                    break;
                                               case ICMP_ECHO:
                                                    reverse->src_port=ICMP_ECHOREPLY;
                                                    break;
                                               case ICMP_TIMESTAMP:
                                                    reverse->src_port=ICMP_TIMESTAMPREPLY;
                                                    break;
                                               case ICMP_TIMESTAMPREPLY:
                                                    reverse->src_port=ICMP_TIMESTAMP;
                                                    break;
                                               default:
                                                     reverse->src_port=icmp_header->type;
                                         }

                          }
                          break;

    }
    return rvalue;


}

/////////////////////////////////////////////
int Flow_helpers::update_l4_stats(const struct Tagged_IP_Packet *inpacket,  Flow_Stats *src_stats ,Flow_Stats *dst_stats){
//int Flow_helpers::update_tcp_flags(const struct tcphdr* tcp_hdr, Flow_stats *src_stats ,Flow_Stats *dst_stats){
  //assume it is forward... (for easier understanding, for now)
  //this assunmes checksum is correct, need to add function to do this!!
  struct tcphdr* tcp_hdr;
  struct ip *ip_header;
 
  ip_header=(struct ip*)(inpacket->data+inpacket->ip_header_offset);
  switch(ip_header->ip_p){
         case IPPROTO_TCP: 
                tcp_hdr=(struct tcphdr*)(inpacket->data +inpacket->ip_header_offset+ip_header->ip_hl*4);
               //increment counters... 
               //first forward then reverse
               if (src_stats->l4.tcp.last_seq>=ntohl(tcp_hdr->seq))
                   src_stats->l4.tcp.non_inc_seq++;
               if ((src_stats->l4.tcp.last_ack>=ntohl(tcp_hdr->ack_seq) ) && (tcp_hdr->ack!=0)){
                    src_stats->l4.tcp.non_inc_ack++;
               }
               //if(target->stats.dst.l4.tcp.last_seq+)
               // mod_between(unsigned int a, unsigned int delta, unsigned int b)
               if(! mod_between(dst_stats->l4.tcp.last_ack, dst_stats->l4.tcp.last_window, ntohl(tcp_hdr->seq) )){
                     src_stats->l4.tcp.out_of_window_seq++;
               }
               if (! mod_between(ntohl(tcp_hdr->ack_seq),ntohs(tcp_hdr->window), dst_stats->l4.tcp.last_seq )){
                   src_stats->l4.tcp.out_of_window_ack++;
               }
               //change state
               src_stats->l4.tcp.last_ack=ntohl(tcp_hdr->ack_seq);
               src_stats->l4.tcp.last_seq=ntohl(tcp_hdr->seq);
               src_stats->l4.tcp.last_window=ntohs(tcp_hdr->window);
  }
  return 0;
}


////////////////////////////////
//Bidir class.... Do we really need it?
///////////////////////////////////////////////////////////

int Bidir_active_flow_db::update_db_with(Tagged_IP_Packet *inpacket){
   //convert packet into flow,
   //search for flow
   // if found update
   // if not add (flow and indexes..)
   map<Active_flow_indexer,list<Tagged_IPV4_Flow>::iterator>::iterator position;
   Tagged_IPV4_Flow forward,reverse, side_effected;
   int rvalue;
   Active_flow_indexer current; 

   rvalue=Flow_helpers::packet_to_ipv4_flows(inpacket,&forward,&reverse,&side_effected,true); 

   if(rvalue<0){
      return rvalue;
   }  
                                               
   switch(rvalue){
         case 0:
          //find reverse, if found update
          //else find forward if found update
          // else insert forward flow, insert index values
          current.create_from_flow(&reverse); 
          position=index.find(current);
          if(index.end()!=position){
                //update
          }
          else{
             current.create_from_flow(&forward);
             
          }
          
          break;
         case 1:
          //find forward.. if found update if not found insert
          //find reverse if found update if not found ignore!!!

          break;
         default:
            return -1;

   }
   



   return 0;
}

#endif
