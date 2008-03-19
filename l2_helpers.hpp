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


#ifndef L2_HELPERS_HPP
#define L2_HELPERS_HPP

#include <pcap.h>
#include <netinet/in.h>

class L2_Helpers{
 private:
    inline static int is_ipv4_DLT_EN10MB(const struct pcap_pkthdr* pcap_hdr, const u_char *packet, short offset);
 public:
    inline static int is_ipv4(const struct pcap_pkthdr *pcap_hdr,const u_char *packet,int data_link,short offset);
};

/////////////////////////////////////////
//////Now the public functions
inline int L2_Helpers::is_ipv4(const struct pcap_pkthdr* pcap_hdr,const u_char *packet,int data_link, short offset){

  switch(data_link){
            case DLT_EN10MB: return is_ipv4_DLT_EN10MB( pcap_hdr, packet, offset ); break;
   
             default:
                  return -1;
   }
   


}




/////////////////////////////////////
//// Now the private functions
///////////

////////////////
// All ipv4 helpers must perform:
//    1. Size validation
//    2. frame type validation
//    3. return location of begin of iphdr
/////////////////////

////////functions for different l2 types go here
///////Functions for different l2 types go HERE
inline int L2_Helpers::is_ipv4_DLT_EN10MB(const struct pcap_pkthdr* pcap_hdr, const u_char *packet, short offset ){
    short *type_test_loc;
    //check length
    // min length is 29: ethernet 14 bytes + 5 min for ipv4
    if(      ((pcap_hdr->caplen-offset)< 19) ||((pcap_hdr->len-offset)< 19)   ){
       return -1;
    }
    //check if ip
    // l2 type, ipv4, and minimum ip header length.
    type_test_loc=(short *)((char *)(packet+12+offset));
    if(0x0800!=ntohs(*type_test_loc) || (0x40 != (packet[14+offset] & 0xf0)) || (5>(packet[14+offset] & 0x0f)) ){
       return -1;
    }
    //return appropiate value
    return 14+offset;
};




#endif

