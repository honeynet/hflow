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



#ifndef ENTROPY_FLOW_TAGGER_BLOCK_HPP
#define ENTROPY_FLOW_TAGGER_BLOCK_HPP

#include "element.h"
#include <pcap.h>
#include <math.h>

#define FLOW_TAGGER_LOGN2 0.693147181
#define ENTROPY_TAGGER_LIMIT_POW 7

using namespace std;

////////////////
// this is an extremely naive filter, will make the caplen small for all packets

typedef struct Flow_Entropy_State_Tag{
    uint32_t header_state      __attribute__((packed));
    uint8_t  payload_state[4]  ;//__attribute__((packed));
    //payload state0 ->  count of char 0-127
    //payload state1 ->  count of char 128-255
}Flow_Entropy_State;


//////////////////Class definition
class Entropy_Flow_Tagger_Block: public Processing_Block{
  private:
  public:
    inline int entry_point(const Tagged_Element *in_packet){return entry_point((Tagged_IP_Packet *) in_packet);};
    int entry_point(const Tagged_IP_Packet *in_packet);
    int set_output_point(Processing_Block *out_block);
    int set_output_point(Processing_Block *,int out_index);
    int do_payload_entropy(const Tagged_IP_Packet *in_packet,const Tagged_IPV4_Flow *current_flow, Flow_Entropy_State *current_state);
    int do_payload_header_entropy(const Tagged_IP_Packet *in_packet, Tagged_IPV4_Flow *current_flow, Flow_Entropy_State *current_state);
    int initialize(int numoutputs);
    int unpack_header_state(float *dest,uint32_t *source);
    int pack_header_state(uint32_t *dest,float *source);
    int unpack_header_state64(float *dest,uint64_t *source);
    int pack_header_state64(uint64_t *dest,float *source);
    inline float min_payent_for_hent(float header_entropy){ return .99-(0.3*powf(header_entropy/2.75,ENTROPY_TAGGER_LIMIT_POW))  ;}

    Entropy_Flow_Tagger_Block();
    static float log2f(float in){return logf(in)/FLOW_TAGGER_LOGN2;};
};

////////Class implementation
Entropy_Flow_Tagger_Block::Entropy_Flow_Tagger_Block(){
   initialized=false;
   next_stage=NULL;
   num_outputs=0;
};

int Entropy_Flow_Tagger_Block::initialize(int in_numoutputs){
  int i;

  next_stage =new Processing_Block*[in_numoutputs];
  num_outputs=in_numoutputs;
  for(i=0;i<num_outputs;i++){
     next_stage[i]=NULL;   
  }  
  initialized=true;
  valid_outputs=0;
  return 0; 
};

inline int Entropy_Flow_Tagger_Block::unpack_header_state(float *dest,uint32_t *source){
    int i;
    for(i=0;i<9;i++){
       *dest= ((*source>>(i*3)) & 0x7);
       dest++;
    }
}

inline int Entropy_Flow_Tagger_Block::pack_header_state(uint32_t *dest,float *source){
   int i;
   uint32_t local;
   *dest=*dest & 0xF0000000;
   for(i=0;i<9;i++){
       local=(uint32_t)*source;
       *dest=*dest | ((local&0x7)<<(i*3));
       source++;
    }
}

inline int Entropy_Flow_Tagger_Block::unpack_header_state64(float *dest,uint64_t *source){
    int i;
    for(i=0;i<9;i++){
       *dest= ((*source>>(i*6)) & 0x3F);
       dest++;
    }
}

inline int Entropy_Flow_Tagger_Block::pack_header_state64(uint64_t *dest,float *source){
   int i;
   uint64_t local;
   *dest=0;
   for(i=0;i<9;i++){
       local=(uint64_t)*source;
       *dest=*dest | ((local&0x3F)<<(i*6));
       source++;
    }
}





int Entropy_Flow_Tagger_Block::do_payload_header_entropy(const Tagged_IP_Packet *in_packet, Tagged_IPV4_Flow *current_flow, Flow_Entropy_State *current_state){
   float header_state[9];
   struct ip      *ip_header;
   struct tcphdr  *tcp_header;
   unsigned int offset=in_packet->ip_header_offset;
   unsigned int offset_to_transport;
   unsigned int offset_to_payload;
   uint8_t packet_sel;
   int i;
   const float small_val=0.000001;
   float *payload_entropy;

   float entropy; 
   float total_count;
   unsigned char *current_ptr;
   uint32_t temp;
   const uint32_t packet_limit=60;

   Flow_Entropy_State *state_64=current_state;
   state_64++;


   //check if anything to do...
   if( ((current_state->header_state & 0x80000000)!=0) ||
     //   (current_state->payload_state[3]|current_state->payload_state[2])!=0)
       //(current_flow->stats.packets()>packet_limit)   ||
       (current_flow->stats.packets()<0)    ){
     return 0;
   }
   //fprintf(stderr,".");

   ip_header=(struct ip*) ((in_packet->data) + in_packet->ip_header_offset);

   //check that protocol matches...
   if(current_flow->protocol!=ip_header->ip_p){
         return 0;  //probably an icmp error message
   }
   offset_to_transport=offset+ip_header->ip_hl*4;
   switch(ip_header->ip_p){
           case 6:  tcp_header=(struct tcphdr*)(in_packet->data +offset_to_transport);
                    offset_to_payload=offset_to_transport+tcp_header->doff*4;
                    break;
           case 17: offset_to_payload=offset_to_transport+8;
                    break;
           case 1 : offset_to_payload=offset_to_transport+4; // not true, but doing another switch seems exesive!
                    break;

           default:
                    offset_to_payload=offset_to_transport;
                    break;
   }
   if((in_packet->pcap_hdr->caplen-offset_to_payload<4) || (offset_to_payload-offset-ntohs(ip_header->ip_len)<=0) ){
           return 0; //cannot match!!!
   }
   current_ptr= (unsigned char *)in_packet->data+offset_to_payload;
   //fprintf(stderr,"\\");

   unpack_header_state(header_state,&(current_state->header_state));
   unpack_header_state64(header_state,(uint64_t *)state_64);


   //generate the selector
   packet_sel=((*current_ptr)>>0)%3;
/*   fprintf(stderr,"entro %02x  dir=%0x  locdir=%0x\n",
                       *current_ptr,
                       current_flow->annot[FLOW_ANNOT_PACK_DIR_HIST].as_int32,
                       current_state->header_state>>28);
*/
   //store packet_dir
   current_state->header_state= (current_state->header_state &0x0FFFFFFF ) |
                                (current_state->header_state &0x1FFFFFFF) <<1 |
                                (current_flow->annot[FLOW_ANNOT_PACK_DIR_HIST].as_int32 &0x1)<<28;

   
   total_count=0;
   if((current_state->header_state>>29& 0x1)== ( current_flow->annot[FLOW_ANNOT_PACK_DIR_HIST].as_int32 &0x1) &&
          current_flow->stats.bytes()<10000    
       ){
      return 0;
   }
   else{
#ifdef VERBOSE_ENTROPY
      fprintf(stderr,"entro %02x  dir=%0x  locdir=%0x\n",
                       *current_ptr,
                       current_flow->annot[FLOW_ANNOT_PACK_DIR_HIST].as_int32,
                       current_state->header_state>>28);
#endif
     // fprintf(stderr,"entro sizes: offset%d offset_to_payload%d  ip_size%d capsize%d\n  ",
     //            offset, offset_to_payload,ntohs(ip_header->ip_len),in_packet->pcap_hdr->caplen);
 
      current_ptr++;
      temp=(*current_ptr);
      current_ptr++;
      //temp=temp*256+(*current_ptr);
      //temp=0;
      packet_sel=packet_sel*3+temp%3; // we have our selection

      //incremente the selector!  
      header_state[packet_sel]++;


      //generate total count!
      total_count=header_state[0];
      for(i=1;i<9;i++){
         total_count+=header_state[i];
      }

   }

   //if se have plenty of packets of we will overflow!
   if(total_count>=60 || current_flow->stats.packets()>=packet_limit ||current_flow->stats.bytes()>=10000  ||  header_state[packet_sel]>14.5){
      //fprintf(stderr,"!\n!");
      //do something and mark the flow as done
#ifdef VERBOSE_ENTROPY
      fprintf(stderr,"entropy header state is %08x count=%f\n",current_state->header_state,total_count);
#endif
      current_state->header_state= 0xFFFFFFFF;
      //add something to each flow count so that we can calculate the log!
/*
      for(i=0;i<9;i++)
        header_state[i]+=small_val;
      total_count+=small_val*9;
*/
      for(i=0;i<9;i++){
#ifdef VERBOSE_ENTROPY
        fprintf(stderr,"entro header[%d]=%f\n",i,header_state[i]);
#endif
        header_state[i]=header_state[i]/total_count;
        //fprintf(stderr,"entro header[%d]=%f\n",i,header_state[i]);
        }
      entropy=0;
      for(i=0;i<9;i++)
         entropy-=header_state[i]*log2f(header_state[i]+small_val);
#ifdef VERBOSE_ENTROPY
      fprintf(stderr,"header entropy is %f !!!!!!\n",entropy); 
#endif
      //check for payload entropy
      if((current_state->payload_state[3]|current_state->payload_state[2]) !=0){
         payload_entropy=(float *)&(current_state->payload_state);
         //if((*payload_entropy>0.7 && entropy>2.2) || (*payload_entropy>.98 && entropy>2) || (*payload_entropy>.99)){
         if( (*payload_entropy>0.7) && *payload_entropy>min_payent_for_hent(entropy)  ){
#ifdef VERBOSE_ENTROPY
               fprintf(stderr,"This is azareous. header entropy is %f , payload%f, func=%f\n",entropy,*payload_entropy,min_payent_for_hent(entropy));
#endif

             current_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32=
                        ( (unsigned int)current_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32 | 0x01000000);
         }

      }     

   }
   else{
     //fprintf(stderr,"/"); 
     pack_header_state64((uint64_t *)state_64,header_state);
     pack_header_state(&(current_state->header_state),header_state);
     //fprintf(stderr,"%08x ",current_state->header_state);
   }
   return 0; 
}

int Entropy_Flow_Tagger_Block::do_payload_entropy(const Tagged_IP_Packet *in_packet, const Tagged_IPV4_Flow *current_flow, Flow_Entropy_State *current_state){
   float *entropy;
   float local_calc;
   int i;
   float count[2];  //will make calculation writting eaier
   const int countlimit=80; //this number must be less than 255 so that count does not overflow
   float total_count;   
   struct ip      *ip_header;
   struct tcphdr  *tcp_header;
   unsigned int offset=in_packet->ip_header_offset;
   unsigned int offset_to_transport;
   unsigned int offset_to_payload;
   unsigned char *current_ptr;
   int iter_limit;


   //check if anything to do...
   if( ((current_state->payload_state[3]|current_state->payload_state[2])!=0) ||
       (current_flow->stats.packets()>15)   ||
       (current_flow->stats.packets()<3)    ){
     return 0;
   }
   count[0]=current_state->payload_state[0];
   count[1]=current_state->payload_state[1];

  

   if(count[0]+count[1]<countlimit){
      
     

      ip_header=(struct ip*) ((in_packet->data) + in_packet->ip_header_offset);

      //check that protocol matches...
      if(current_flow->protocol!=ip_header->ip_p){
          return 0;  //probably an icmp error message
      }
      offset_to_transport=offset+ip_header->ip_hl*4;
      switch(ip_header->ip_p){
           case 6:  tcp_header=(struct tcphdr*)(in_packet->data +offset_to_transport);
                    offset_to_payload=offset_to_transport+tcp_header->doff*4;
                    break;
           case 17: offset_to_payload=offset_to_transport+8;
                    break;
           case 1 : offset_to_payload=offset_to_transport+4; // not true, but doing another switch seems exesive!
                    break;

           default:
                    offset_to_payload=offset_to_transport;
                    break;
      }
      if(offset_to_payload>=in_packet->pcap_hdr->caplen){
           return 0; //cannot match!!!
      }
      current_ptr= (unsigned char *)in_packet->data+offset_to_payload;

      for(i=0;i<in_packet->pcap_hdr->caplen-offset_to_payload && (count[0]+count[1]<=countlimit) && (i<=30);i++){
         // fprintf(stderr,"'%u,%2x' offset_p=%x offset_t=%x caplen=%x\n ",
         //                 *current_ptr,*current_ptr, offset_to_payload,offset_to_transport,in_packet->pcap_hdr->caplen);
          count[(*current_ptr)>>7]++;
          current_ptr++;
      }
     
   }
   if(count[0]+count[1]>=countlimit){
      //calculate.. this is so wrong!!
 
      entropy=(float *)&(current_state->payload_state);
       
      if(0==count[0] || 0==count[1] ){
          *entropy=0;
         goto donecalc;
      }

      total_count=count[0]+count[1];

      *entropy=(-count[0]/total_count*log2f(count[0]/total_count)) +
               (-count[1]/total_count*log2f(count[1]/total_count));
      donecalc:
      //current_state->payload_state[3]=current_state->payload_state[3]|0x01;
      *entropy+=0.00000003333333;
#ifdef VERBOSE_ENTROPY
      fprintf(stderr,"Payload entropy is %f counts 0=%f 1=%f\n",*entropy,count[0],count[1]);
#endif
      //current_state->payload_state[3]=current_state->payload_state[3]|0x01;

   }
   else{
      current_state->payload_state[0]=(uint8_t)count[0];
      current_state->payload_state[1]=(uint8_t)count[1];
   }
   return 0;
}


int Entropy_Flow_Tagger_Block::entry_point(const Tagged_IP_Packet *in_packet){
  int i;
  Tagged_IPV4_Flow *current_flow;
  //cout << "inpacket" <<endl;
   ///processs here
   if(in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr!=NULL){
        //I can start to contemplate to do somthing, as there is some flow information.
        current_flow=(Tagged_IPV4_Flow *)(in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr); //ugly
      
       do_payload_entropy(in_packet, current_flow,( Flow_Entropy_State *) &(current_flow->annot[FLOW_ANNOT_ENTRO_STATE].as_int64));          
       do_payload_header_entropy(in_packet, current_flow,( Flow_Entropy_State *) &(current_flow->annot[FLOW_ANNOT_ENTRO_STATE].as_int64));

   }


   // call each valid output
  for(i=0;i<valid_outputs;i++){
     (next_stage[i])->entry_point(in_packet);
  }
  return 0;
}

int Entropy_Flow_Tagger_Block::set_output_point(Processing_Block *out_block){
   
  if (false==initialized){
     initialize(1);
  }
  next_stage[0]=out_block;
  if (valid_outputs<1){
     valid_outputs=1;
  };
  return 0;
}

#endif
