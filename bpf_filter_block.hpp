// (C) 2007 The Trustees of Indiana University.  All rights reserved.
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


#ifndef BPF_FILTER_BLOCK_HPP
#define BFP_FILTER_BLOCK_HPP

#include "element.h"
#include <pcap.h>
#include <pcap-bpf.h>
#include <map>
#include <list>
#include <iostream>

using namespace std;

//////////////////Class definition
class BPF_Filter: public Processing_Block{
  private:
    struct bpf_program bpf_prog;
    pcap_t *pcap_descr;
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip wtf?*/
    bool valid_filter;
  public:
    inline int entry_point(const Tagged_Element *in_packet){return entry_point((Tagged_IP_Packet *) in_packet);};
    int entry_point(const Tagged_IP_Packet *in_packet);
    int set_output_point(Processing_Block *out_block);
    int set_output_point(Processing_Block *,int out_index);
    int initialize(int numoutputs,char *bpf_filter_string, int linktype);
    int set_filter(char *bpf_filter_string, int linktype);
    BPF_Filter();
    bool is_valid(){return valid_filter;};
};

////////Class implementation
BPF_Filter::BPF_Filter(){
   initialized=false;
   next_stage=NULL;
   num_outputs=0;
   valid_filter=false;
};

int BPF_Filter::set_filter(char *bpf_filter_string, int linktype){
   if (NULL==bpf_filter_string)
       return -1;
   //should we do a pcap_close? before?
   pcap_descr=pcap_open_dead(linktype,MAX_PACKET_PAYLOAD_LENGTH);
   if(NULL==pcap_descr){
       perror("cannot make dead pcap struct for bpf filter");
       return -1;
       }
   if(-1== pcap_compile(pcap_descr,&bpf_prog,bpf_filter_string,0,netp)){
       perror("error compiling bpf program");
       return -1;
       }

  
   valid_filter=true;
   return 0;
}



int BPF_Filter::initialize(int in_numoutputs,char *bpf_filter_string,int linktype){
  int i;

  next_stage =new Processing_Block*[in_numoutputs];
  num_outputs=in_numoutputs;
  for(i=0;i<num_outputs;i++){
     next_stage[i]=NULL;   
     }  
 
  if(NULL!=bpf_filter_string){
     pcap_descr=pcap_open_dead(linktype,MAX_PACKET_PAYLOAD_LENGTH);
     if(NULL==pcap_descr){
         perror("cannot make dead pcap struct for bpf filter");
         exit(1);
         }
     if(-1== pcap_compile(pcap_descr,&bpf_prog,bpf_filter_string,0,netp)){
         perror("error compiling bpf program");
         exit(1);
         }
     valid_filter=true;
     }

  initialized=true;
  valid_outputs=0;
  return 0; 
};


int BPF_Filter::entry_point(const Tagged_IP_Packet *in_packet){
  int i;
  //bpf_insn *local_test=bpf_prog.bf_insns;
  //cout << "inpacket" <<endl;
   ///processs here
   if(valid_filter){
      //run the filter
      if (0!=bpf_filter(bpf_prog.bf_insns,
                        //local_test,
                        in_packet->data,
                        in_packet->pcap_hdr->len,
                        in_packet->pcap_hdr->caplen)){ //we got data
         for(i=0;i<valid_outputs;i++){
              (next_stage[i])->entry_point(in_packet);
              }
         
          }      

      }
   else{
   // call each valid output
      for(i=0;i<valid_outputs;i++){
         (next_stage[i])->entry_point(in_packet);
        } 
   }
  return 0;
}

int BPF_Filter::set_output_point(Processing_Block *out_block){
   
  if (false==initialized){
     initialize(1,NULL,0);
  }
  next_stage[0]=out_block;
  if (valid_outputs<1){
     valid_outputs=1;
  };
  return 0;
}

#endif
