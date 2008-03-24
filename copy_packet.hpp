#ifndef COPY_PACKET_HPP
#define COPY_PACKET_HPP


#include "element.h"
#include <string.h>

//
//This is an extremely dangerous class, as it keeps 
//



class Copy_Packet : public Tagged_Packet{
 public:
  int packet_type;
  struct pcap_pkthdr true_pcap_hdr;
  u_char pkt_data[MAX_PACKET_PAYLOAD_LENGTH];

   int fill_from_packet2(const Copy_Packet *in_packet){
      //true_pcap_hdr=*(in_packet->pcap_hdr);
      memcpy(annot,in_packet->annot,sizeof(Element_Annotation)*MAX_ANNOT_PER_ELEMENT);
      memcpy(&true_pcap_hdr,in_packet->pcap_hdr,sizeof(struct pcap_pkthdr));
      memcpy(pkt_data,in_packet->data,true_pcap_hdr.caplen);
      pcap_hdr=&true_pcap_hdr;
      //packet_type=in_packet->get_packet_type();
      return 0;
      };
   int fill_from_packet2(const Tagged_Packet *in_packet){
      //true_pcap_hdr=*(in_packet->pcap_hdr);
      memcpy(annot,in_packet->annot,sizeof(Element_Annotation)*MAX_ANNOT_PER_ELEMENT);
      memcpy(&true_pcap_hdr,in_packet->pcap_hdr,sizeof(struct pcap_pkthdr));
      memcpy(pkt_data,in_packet->data,true_pcap_hdr.caplen);
      pcap_hdr=&true_pcap_hdr;
      //packet_type=in_packet->get_packet_type();
      return 0;
      };
  int fill_from_packet(const Tagged_IP_Packet *in_packet){
      memcpy(annot,in_packet->annot,sizeof(Element_Annotation)*MAX_ANNOT_PER_ELEMENT);
      //true_pcap_hdr=*(in_packet->pcap_hdr);
      memcpy(&true_pcap_hdr,in_packet->pcap_hdr,sizeof(struct pcap_pkthdr));
      //memcpy(pkt_data,in_packet->data,in_packet->pcap_hdr->len);
      memcpy(pkt_data,in_packet->data,true_pcap_hdr.len);
      pcap_hdr=&true_pcap_hdr;
      //packet_type=in_packet->get_packet_type();
      return 0;
      };
  Copy_Packet(){
      //memset(&true_pcap_hdr,0x00,sizeof(struct pcap_pkthdr));
      pcap_hdr=&true_pcap_hdr;
      data=pkt_data;
      };
  ~Copy_Packet(){
      pcap_hdr=NULL;
      data=NULL;
   }
  Copy_Packet(const Tagged_Packet &build_from){
      //broken
      if (this != &build_from){
        fill_from_packet2(&build_from);
        pcap_hdr=&true_pcap_hdr;
        data=pkt_data;
        }
      };

  Copy_Packet(const Tagged_IP_Packet &build_from){
      //if (this != &build_from){
        fill_from_packet(&build_from);
        //Stand_Alone_Packet();
        pcap_hdr=&true_pcap_hdr;
        data=pkt_data;
       // }
      };
  Copy_Packet(const Copy_Packet &build_from){
      // fill_from_packet(&source);
      if(this !=&build_from){
         fill_from_packet2(&build_from);
         pcap_hdr=&true_pcap_hdr;
         data=pkt_data;

         //Stand_Alone_Packet();
         }
      };


  Copy_Packet& operator=(const Tagged_Packet &source){
      if(this!=&source){
        fill_from_packet2(&source);
        //true_pcap_hdr=*(in_packet->pcap_hdr);
        //memcpy(pkt_data,in_packet->data,in_packet->pcap_hdr->len);
        //memcpy(annot,in_packet->annot,sizeof(Element_Annotation)*MAX_ANNOT_PER_ELEMENT);
        //Stand_Alone_Packet();
        pcap_hdr=&true_pcap_hdr;
        data=pkt_data;

        }
      return *this;
      };

  Copy_Packet& operator=(const Tagged_IP_Packet &source){
     // if(this!=&source){
        fill_from_packet(&source);
        //Stand_Alone_Packet();
        pcap_hdr=&true_pcap_hdr;
        data=pkt_data;

       // }
      return *this;
      };
  Copy_Packet& operator=(const Copy_Packet &source){
      if(this!=&source){

        // fill_from_packet(&source);
        memcpy(&true_pcap_hdr,&source.true_pcap_hdr,sizeof(struct pcap_pkthdr));
        memcpy(pkt_data,source.pkt_data,source.true_pcap_hdr.caplen);
        pcap_hdr=&true_pcap_hdr;
        data=pkt_data;


        }
      return *this;
      };


};

#endif
