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



#ifndef MARKER_FILTER_BLOCK_HPP
#define MARKER_FILTER_BLOCK_HPP

#include "element.h"
#include <pcap.h>
#include <map>
#include <list>
#include <iostream>

#define MAX_FRAG_PACKET_SIZE 10000

using namespace std;

////////////////
// this is an extremely naive filter, will make the caplen small for all packets
// that have a known match.


//////////////////Class definition
class Marker_Filter_Block: public Processing_Block{
  private:
  public:
    inline int entry_point(const Tagged_Element *in_packet){return entry_point((Tagged_IP_Packet *) in_packet);};
    int entry_point(const Tagged_IP_Packet *in_packet);
    int set_output_point(Processing_Block *out_block);
    int set_output_point(Processing_Block *,int out_index);
    int initialize(int numoutputs);
    bool drop_long;
    uint32_t long_size;
    Marker_Filter_Block();
};

////////Class implementation
Marker_Filter_Block::Marker_Filter_Block(){
   initialized=false;
   long_size=10000;
   drop_long=false;
   next_stage=NULL;
   num_outputs=0;
};

int Marker_Filter_Block::initialize(int in_numoutputs){
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


int Marker_Filter_Block::entry_point(const Tagged_IP_Packet *in_packet){
  int i;
  Tagged_IPV4_Flow *current_flow;
  //cout << "inpacket" <<endl;
   ///processs here
   if(in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr!=NULL){
        //I can start to contemplate to do somthing, as there is some flow information.
        current_flow=(Tagged_IPV4_Flow *)(in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr); //ugly
        if (  (((unsigned int )current_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32 | FLOW_MARKER_DONE_TAG)!=FLOW_MARKER_DONE_TAG)  ||
              (true==drop_long && current_flow->stats.bytes()>long_size)  ) {
            //there is omething to be said about this flow....
            if(in_packet->pcap_hdr->caplen>80){
                in_packet->pcap_hdr->caplen=80;
            }
        }
   }


   // call each valid output
  for(i=0;i<valid_outputs;i++){
     (next_stage[i])->entry_point(in_packet);
  }
  return 0;
}

int Marker_Filter_Block::set_output_point(Processing_Block *out_block){
   
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
