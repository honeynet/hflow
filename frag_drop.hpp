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



#ifndef FRAG_DROP_HPP
#define FRAG_DROP_HPP

#include "element.h"
#include <pcap.h>
#include <map>
#include <list>
#include <iostream>

#define MAX_FRAG_PACKET_SIZE 10000

using namespace std;

//////////////////Class definition
class Frag_Drop: public Processing_Block{
  private:
    Processing_Block *fragmented_out;
  public:
    inline int entry_point(const Tagged_Element *in_packet){return entry_point((Tagged_IP_Packet *) in_packet);};
    int entry_point(const Tagged_IP_Packet *in_packet);
    int set_output_point(Processing_Block *out_block);
    int set_output_point(Processing_Block *,int out_index);
    int initialize(int numoutputs);
    Frag_Drop();
};

////////Class implementation
Frag_Drop::Frag_Drop(){
   initialized=false;
   next_stage=NULL;
   num_outputs=0;
   fragmented_out=NULL;
};

int Frag_Drop::initialize(int in_numoutputs){
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


int Frag_Drop::entry_point(const Tagged_IP_Packet *in_packet){
  int i;
  cout << "inpacket" <<endl;
   ///processs here


   // call each valid output
  for(i=0;i<valid_outputs;i++){
     (next_stage[i])->entry_point(in_packet);
  }
  return 0;
}

int Frag_Drop::set_output_point(Processing_Block *out_block){
   
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
