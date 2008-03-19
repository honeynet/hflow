
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


#ifndef PCAP_RAW_INFILE_BLOCK_HPP
#define PCAP_RAW_INFILE_BLOCK_HPP

#include "element.h"
//#include "l2_helpers.hpp"
#include <pcap.h>
#include <map>
#include <list>
#include <iostream>
#include <stdio.h>

using namespace std;

//////////////////Class definition
class Pcap_Raw_Infile_Block: public Processing_Block{
  private:
    pcap_t *pcap_descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    int offset_to_ipv4_header;
    int offset_to_hdlc_type;
    bool const_offset;
    int data_link;
    unsigned long num_iters;
  public:
    bool with_loop;
    Tagged_IP_Packet out_packet;
  public:
    static void call_back_entry_point(u_char* inval,const struct pcap_pkthdr* pkthdr, const u_char* packet){
       ((Pcap_Raw_Infile_Block *)inval)->entry_point2(pkthdr,packet);
    };
    inline int entry_point(const Tagged_Element *in_packet){return entry_point((Tagged_IP_Packet *) in_packet);};
    int entry_point(const Tagged_IP_Packet *in_packet);
    int entry_point2(const pcap_pkthdr* pkhdr,const u_char *pkt_data);
    int set_output_point(Processing_Block *out_block);
    int set_output_point(Processing_Block *,int out_index);
    int initialize(int numoutputs,char *filename);
    int initialize(int numoutputs,char *dev_or_filename,int type);
    int get_linktype(){return data_link;};
    int get_print_stats();
    Pcap_Raw_Infile_Block();
    ~Pcap_Raw_Infile_Block();
};

////////Class implementation
Pcap_Raw_Infile_Block::~Pcap_Raw_Infile_Block(){
    if (NULL!=pcap_descr){
       pcap_close(pcap_descr);
    }
};

Pcap_Raw_Infile_Block::Pcap_Raw_Infile_Block(){
   initialized=false;
   next_stage=NULL;
   pcap_descr=NULL;
   num_outputs=0;
};


int Pcap_Raw_Infile_Block::initialize(int in_numoutputs,char *in_filename){
   return initialize(in_numoutputs,in_filename,0);
};

int Pcap_Raw_Infile_Block::initialize(int in_numoutputs,char *in_filename,int type){
  int i;

  next_stage =new Processing_Block*[in_numoutputs];
  num_outputs=in_numoutputs;
  for(i=0;i<num_outputs;i++){
     next_stage[i]=NULL;   
  }  
  //open pcap
  if(0==type)
     pcap_descr=pcap_open_offline(in_filename,errbuf);
  else{
     pcap_descr = pcap_open_live(in_filename,MAX_PACKET_PAYLOAD_LENGTH,1,-1,errbuf);
     //pcap_descr = pcap_open_live(in_filename,400,1,-1,errbuf);
     live_read=true;
  }
  if(pcap_descr == NULL)
  { printf("pcap_open_offline(): %s\n",errbuf); exit(1); }

  //setup datalink
  data_link=pcap_datalink(pcap_descr);
 
  initialized=true;
  valid_outputs=0;
  return 0; 
};




int Pcap_Raw_Infile_Block::entry_point(const Tagged_IP_Packet *in_packet){
  
  //cout << "inpacket" <<endl;
   ///processs here .. will always do loop for now
     //Do pcap loop here
  int rvalue=0;
  long int total_recv=0,total_drop=0;;
  struct pcap_stat last_loop_stats;
  do{
       rvalue=pcap_loop(pcap_descr,-1,call_back_entry_point,(u_char *)this);
       pcap_stats(pcap_descr,&last_loop_stats);
       total_recv+=last_loop_stats.ps_recv;
       total_drop+=last_loop_stats.ps_drop;
       if(last_loop_stats.ps_drop!=0){
          cout << "recv_imp="<< last_loop_stats.ps_recv ;
          cout <<" drop"<<last_loop_stats.ps_drop ;
          //cout <<" if drop"<< last_loop_stats.ps_ifdrop ;
          cout <<" total recv="<<total_recv;
          cout <<" total drop="<<total_drop; 
          cout << "capture ratio =" <<(1.0-total_drop/(1.0*total_recv));
          cout << endl;
          //cout <<"capt" << last_loop_stats.ps_capt<<endl;
       }
  }while(0==rvalue &&true==live_read);
  return rvalue;
  //return pcap_loop(pcap_descr,-1,call_back_entry_point,(u_char *)this);
}



int Pcap_Raw_Infile_Block::entry_point2(const struct pcap_pkthdr* pkhdr,const u_char *pkt_data){
  int i;
  //int offset;

  //cout << "inpentry2" <<endl;
  out_packet.pcap_hdr=(struct pcap_pkthdr*)pkhdr;
  out_packet.data=(u_char* )pkt_data;
 
  //setup ptr to
  //offset=L2_Helpers::is_ipv4(pkhdr,pkt_data,data_link,0);
  //if (offset<0){return 0;}
  //out_packet.ip_header_offset=offset;

   // call each valid output
  for(i=0;i<valid_outputs;i++){///ok I will use a cast for now, but I
                               //am not sure of its correctness
     (next_stage[i])->entry_point(&out_packet);
  }
  if(0x01==(num_iters & 0x3FFFF)){
      get_print_stats();
  }

  num_iters++;
  return 0;
}

int Pcap_Raw_Infile_Block::set_output_point(Processing_Block *out_block){
   
  if (false==initialized){
     return -1;
  }
  next_stage[0]=out_block;
  if (valid_outputs<1){
     valid_outputs=1;
  };
  return 0;
};

int Pcap_Raw_Infile_Block::get_print_stats(){

  struct pcap_stat last_loop_stats;

  pcap_stats(pcap_descr,&last_loop_stats);

// if(last_loop_stats.ps_drop!=0){
     cout << "recv="<< last_loop_stats.ps_recv ;
     cout <<" drop"<<last_loop_stats.ps_drop ;
     //cout <<" if drop"<< last_loop_stats.ps_ifdrop ;
     cout << "capture ratio =" <<(1.0-last_loop_stats.ps_drop/(1.0*last_loop_stats.ps_recv));
     cout << endl;
//}
  return 0;
};


#endif
