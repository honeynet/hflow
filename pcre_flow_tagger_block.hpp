// (C) 2006 The Trustees of Indiana University, Camilo Viecco.  All rights reserved.
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
//
//  This module requires -pthread and -lpcre



#ifndef PCRE_FLOW_TAGGER_HPP
#define PCRE_FLOW_TAGGER_HPP


///#include "config.h"

#include "element.h"
#include "copy_packet.hpp"
#include <pcap.h>
#include <map>
#include <list>
#include <iostream>
//#include <pcre/pcre.h>

#ifdef HAVE_PCRE_PRCE_H 
#include <pcre/pcre.h>
#else
#include <pcre.h>
#endif


//enums:
#include <netinet/in.h>

//structs //needed to pinpoint the payload starting point!!
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>


#define MAX_PCRE_MATCH_TYPES 16
#define MAX_PCRE_RULES_PER_TYPE 7
#define PCRE_POSSIBLE_MATCH 0x80
#define MAX_SIMULTANEOUS_MATCHING_FLOWS 1000
#define MAX_SEC_TO_MATCH 20
#define PCRE_EXEC_OVECCOUNT 30

/*#define VERBOSE_PCRE*/

using namespace std;

//////////

class Per_flow_pcre_state{
  public:
     list<Per_flow_pcre_state>::iterator iter_to_self;
     uint8_t state[MAX_PCRE_MATCH_TYPES];
     unsigned int last_time;
     Per_flow_pcre_state(){
         memset(state,0x00,sizeof(uint8_t)*MAX_PCRE_MATCH_TYPES);
     }
};

class Pcre_rule_limits{
  public:
     unsigned int min_bytes;
     unsigned int max_bytes;
     unsigned int min_packets;
     unsigned int max_packets;
     uint8_t proto;
  public:
     Pcre_rule_limits(){
        min_bytes=0x7FFFFFFF;
        max_bytes=0;
        min_packets=0x7FFFFFFF;
        max_packets=0;
     };
     bool still_possible(unsigned int packets,unsigned int bytes){
         if(packets<=max_packets && bytes<=max_bytes)
            return true;
         else
            return false;
     };
     bool possible(unsigned int packets,unsigned int bytes){
         if(packets>=min_packets && packets<=max_packets && bytes>=min_bytes && bytes<=max_bytes)
            return true;
         else
            return false;
     };
};


class Pcre_type_rule{
  public:
     Pcre_rule_limits limit;
     pcre *re;
     pcre_extra *pe;
     bool client;
     bool server;
 public:
    Pcre_type_rule(){
       re=NULL;
       pe=NULL;
       client=false;
       server=false;
    };
};

class Pcre_type_data{
  public:
     Pcre_rule_limits limit;
     Pcre_type_rule rule[MAX_PCRE_RULES_PER_TYPE];
     uint8_t num_rules;
     uint8_t initial_val;
  public:
     Pcre_type_data(){
       num_rules=0;
       initial_val=0;
     }
};


//////////////////Class definition
class Pcre_Flow_Tagger: public Processing_Block{
  private:
    //Pcre_Flow_Tagger *fragmented_out;
    Pcre_rule_limits limit;
    Pcre_type_data matcher[MAX_PCRE_MATCH_TYPES];
    Tagged_IPV4_Flow *current_flow;
    int num_active;
    list<Per_flow_pcre_state> pending_state_list;
    Per_flow_pcre_state default_flow_state;
    //----------
    list <Copy_Packet> packet_queue;
    pthread_t sebek_processing_thread;
    pthread_mutex_t in_queue_mutex;
    sem_t queue_sem;
    sem_t done_sem;
    volatile bool input_done;
    struct timespec delay;


  public:
    inline int entry_point(const Tagged_Element *in_packet){return entry_point((Tagged_IP_Packet *) in_packet);};
    int entry_point(const Tagged_IP_Packet *in_packet);
    int set_output_point(Processing_Block *out_block);
    int set_output_point(Processing_Block *,int out_index);
    int initialize(int numoutputs);
    int load_rules_from_file(const char *filename);
    int do_matching(const Tagged_IP_Packet *in_packet, Per_flow_pcre_state *flow_state);
    int internal_collector();
    Pcre_Flow_Tagger();
};

//next func, maybe static function better?
void *pcre_flow_tagger_thread_func(void *inblock){
             Pcre_Flow_Tagger *in_class;
             in_class=(Pcre_Flow_Tagger *)inblock;
             in_class->internal_collector();
             return NULL;
};


////////Class implementation
Pcre_Flow_Tagger::Pcre_Flow_Tagger(){
   initialized=false;
   next_stage=NULL;
   num_outputs=0;
   num_active=0;
};

int Pcre_Flow_Tagger::initialize(int in_numoutputs){
  int i;

  next_stage =new Processing_Block*[in_numoutputs];
  num_outputs=in_numoutputs;
  for(i=0;i<num_outputs;i++){
     next_stage[i]=NULL;   
  }  
  //load parametres from file
  if (0>load_rules_from_file("pcre.rules")){
    fprintf(stderr,"error while loading rules, aborting\n");
    exit(1);
  } 
 
  //create work thread....

  initialized=true;
  valid_outputs=0;
  return 0; 
};


int Pcre_Flow_Tagger::entry_point(const Tagged_IP_Packet *in_packet){
  int i;
  list<Per_flow_pcre_state>::iterator iter;
  Per_flow_pcre_state *to_save;
  unsigned int dir_bytes,dir_packets;
    //cout << "Pcre inpacket" <<endl;
   ///processs here
   if(in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr!=NULL){
        //I can start to contemplate to do somthing, as there is some flow information.
        current_flow=(Tagged_IPV4_Flow *)(in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr); //ugly
        //we are doing something awful, reading from a possibly invalid memory location or
        // a no longer valid memory location, this could work for real time, but problems could
        // arise when reading from files..
        // two options exist... slow down the reader OR use locking I wish I could do without locking
        // the other big assumtion here is the fact that the system reads a whole 32bit word at a time....

        //get the directionality packets and bytes
 /*       if(in_packet->annot[PACKET_ANNOT_PACK_DIR].as_int32==PACKET_TAG_DIR_FORWARD){
         dir_bytes  =current_flow->stats.src.bytes;
          //dir_packets=current_flow->stats.src.packets;
        }
        else{
          //if(in_packet->annot[PACKET_ANNOT_PACK_DIR]==PACKET_TAG_DIR_REVERSE)
          dir_bytes  =current_flow->stats.dst.bytes;
          dir_packets=current_flow->stats.dst.packets;
        }
*/
        if(current_flow->stats.dst.bytes>current_flow->stats.src.bytes){
           dir_bytes=current_flow->stats.src.bytes;
        }
        else{
           dir_bytes=current_flow->stats.dst.bytes;
        }


        if(current_flow->stats.dst.packets>current_flow->stats.src.packets){
           dir_packets=current_flow->stats.src.packets;
        }
        else{
           dir_packets=current_flow->stats.dst.packets;
        }



        if (((unsigned int )current_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32 & FLOW_MARKER_DONE_TAG)!=FLOW_MARKER_DONE_TAG){           
            //we can start to attempting to add info....
            //check if not allocated, and add if possbile
            if(NULL==current_flow->annot[FLOW_ANNOT_MARKER_STATE].as_ptr){
                  //if we have empty slots, allocate one, and still possible to match allocate
                  if(limit.still_possible(current_flow->stats.packets(),current_flow->stats.bytes() )){
                      //only try to allocate if suffient space AND at least min work has been done
                      if(num_active<MAX_SIMULTANEOUS_MATCHING_FLOWS && current_flow->stats.packets()>=limit.min_packets){
                         //allocate!!!
                         //if(pending_state_list.empty()){
                            default_flow_state.iter_to_self=pending_state_list.begin();
                         //else{
                            //default_flow_state.iter_to_self=pending_state_list.end();
                         //}

                         default_flow_state.last_time=current_flow->stats.end_time();
                         pending_state_list.push_front(default_flow_state);
                         //set up the pointer and store it (done in two steps so that compiler help us catch errors)
                         //to_save=&(*(default_flow_state.iter_to_self)); 
                         to_save=&(*(pending_state_list.begin()));                         
                         current_flow->annot[FLOW_ANNOT_MARKER_STATE].as_ptr=to_save;
                         to_save->iter_to_self=pending_state_list.begin();
                      }
                    
                  }
                  else{
                     //cannot do flow, again an ugly assignment
                     current_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32=FLOW_MARKER_DONE_TAG;
                  }
                  
            }
            if(NULL!=current_flow->annot[FLOW_ANNOT_MARKER_STATE].as_ptr){
                // data is available
                // check if still possble, if not, free space, mark as DONE
                to_save=(Per_flow_pcre_state *) current_flow->annot[FLOW_ANNOT_MARKER_STATE].as_ptr;
                //if(limit.still_possible(current_flow->stats.packets(),current_flow->stats.bytes() )){
                if(limit.still_possible(current_flow->stats.packets(),dir_bytes )){
                    // perform matching!!!!!
                    //fprintf(stderr,",");
                    do_matching(in_packet, to_save);
                }
                else{
                   //do cleanup
                   //fprintf(stderr,"on cleanup flow_packets=%d flow_bytes=%d",current_flow->stats.packets(),current_flow->stats.bytes());
                   //fprintf(stderr,"on cleanup flow_packets=%d flow_bytes=%d\n",current_flow->stats.packets(),dir_bytes);
                   current_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32=
                                      (FLOW_MARKER_DONE_TAG | (unsigned int) current_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32) ; 
                   to_save=(Per_flow_pcre_state *) current_flow->annot[FLOW_ANNOT_MARKER_STATE].as_ptr;
                   current_flow->annot[FLOW_ANNOT_MARKER_STATE].as_ptr=NULL;
                   pending_state_list.erase(to_save->iter_to_self);
                }
            }
            
        }
   }

   // call each valid output
  for(i=0;i<valid_outputs;i++){
     (next_stage[i])->entry_point(in_packet);
  }
  return 0;
}

int Pcre_Flow_Tagger::set_output_point(Processing_Block *out_block){
   
  if (false==initialized){
     initialize(1);
  }
  next_stage[0]=out_block;
  if (valid_outputs<1){
     valid_outputs=1;
  };
  return 0;
}


int  Pcre_Flow_Tagger::do_matching(const Tagged_IP_Packet *in_packet, Per_flow_pcre_state *flow_state){
   //assumes current_flow is done correctly
   // assumes headers are in packet!!!! (again on assertion that flow is mentioned for this packet!!)
   // so no fragmented packets can reach here !!!
   int i,j;
   struct ip      *ip_header;
   struct tcphdr  *tcp_header;
   //struct icmphdr *icmp_header;
   int rc;
   int ovector[PCRE_EXEC_OVECCOUNT];

   unsigned int offset=in_packet->ip_header_offset;   
   unsigned int offset_to_transport;
   unsigned int offset_to_payload;


   unsigned int dir_bytes,dir_packets;
   bool packet_server=false;
   bool packet_client=false;

#ifdef VERBOSE
#ifdef VERBOSE_PCRE
   fprintf(stderr,"pcre: do_matching called flow_packets=%d flow_bytes=%d \n",current_flow->stats.packets(),current_flow->stats.bytes());
#endif
#endif
   ip_header=(struct ip*) ((in_packet->data) + in_packet->ip_header_offset);

   //check that protocol matches...
   if(current_flow->protocol!=ip_header->ip_p){
        return 0;  //probably an icmp error message
   }
   offset_to_transport=offset+ip_header->ip_hl*4;   
   switch(ip_header->ip_p){
        case 6: tcp_header=(struct tcphdr*)(in_packet->data +offset_to_transport);
                offset_to_payload=offset_to_transport+tcp_header->doff*4;
                break;
        case 17: offset_to_payload=offset_to_transport+8;
                break;
        case 1 :offset_to_payload=offset_to_transport+4; // not true, but doing another switch seems exesive!
                break;
        
        default:
                offset_to_payload=offset_to_transport;
                break;
   }
   if(offset_to_payload>=in_packet->pcap_hdr->caplen){
      return 0; //cannot match!!!
   }
   //get the directionality packets and bytes
   if(in_packet->annot[PACKET_ANNOT_PACK_DIR].as_int32==PACKET_TAG_DIR_FORWARD){
      dir_bytes  =current_flow->stats.src.bytes;
      dir_packets=current_flow->stats.src.packets;
      packet_client=true;
   }
   else{
     //if(in_packet->annot[PACKET_ANNOT_PACK_DIR]==PACKET_TAG_DIR_REVERSE)
     dir_bytes  =current_flow->stats.dst.bytes;
     dir_packets=current_flow->stats.dst.packets;
     packet_server=true;
   }
   

   //now the actual checking!!!
   for(i=0;i<MAX_PCRE_MATCH_TYPES;i++){
      //fprintf(stderr,"pcre: do_matching matcher[%d] : min_bytes=%d,max_bytes=%d min_packets=%d, max_packets=%d\n",
      //                                          i,matcher[i].limit.min_bytes,matcher[i].limit.max_bytes,
      //                                            matcher[i].limit.min_packets,matcher[i].limit.max_packets);

//      if(matcher[i].limit.possible(current_flow->stats.packets(),current_flow->stats.bytes() )){
      if(matcher[i].limit.possible(current_flow->stats.packets(),dir_bytes)){
#ifdef VERBOSE_PCRE
          fprintf(stderr,"pcre: do_matching matcher[%d] possible match_size=%d offset_p=%x offset_t=%x\n",
                                                    i, 
                                                    in_packet->pcap_hdr->caplen-offset_to_payload,
                                                    offset_to_payload,
                                                    offset_to_transport);
;
          fprintf(stderr,"pcre: do_matching matcher[%d] state=%x\n",i,flow_state->state[i]);
#endif
         for(j=0;j<matcher[i].num_rules;j++){
//            if(matcher[i].rule[j].limit.possible(current_flow->stats.packets(),current_flow->stats.bytes())){
             if(matcher[i].rule[j].limit.possible(current_flow->stats.packets(),dir_bytes)
                 && ((packet_client && matcher[i].rule[j].client) ||  (packet_server && matcher[i].rule[j].server ) ) 
                   ){ 
             //do the pcre match here!!!!!
               rc = pcre_exec(
                          matcher[i].rule[j].re,       /* the compiled pattern */
                          matcher[i].rule[j].pe,       /* no extra data  */
                          //argv[2],              /* the subject string */
                          (char *)in_packet->data+offset_to_payload,
                          //(int)strlen(argv[2]), /* the length of the subject */
                          in_packet->pcap_hdr->caplen-offset_to_payload,
                          0,                    /* start at offset 0 in the subject */
                          0,                    /* default options */
                          ovector,              /* output vector for substring information */
                          PCRE_EXEC_OVECCOUNT);           /* number of elements in the output vector */
               //fprintf(stderr,"executed pcre_exec!\n");

#ifdef VERBOSE
#ifdef VERBOSE_PCRE
              if (rc < 0)
                   {
                   switch(rc) {
                       case PCRE_ERROR_NOMATCH: fprintf(stderr,"No match\n"); break;
                       default                : fprintf(stderr,"Matching error %d\n", rc); break;
                   }
              }
#endif
#endif
              if(rc>=0){
                  //sucessful match
#ifdef VERBOSE_PCRE
                  fprintf(stderr,"Pcre match found! type=%d rule%d\n",i,j);
#endif
                  flow_state->state[i]=flow_state->state[i] | (0x1 <<j); 
                  if(0xFF==flow_state->state[i]){
                      current_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32= 
                        ( (unsigned int)current_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32 | (0x1<<i));
                  }                 
              }     
            }
         }
      }
   }
   
   return 0; 
}


int Pcre_Flow_Tagger::load_rules_from_file(const char *filename){
   int rvalue=-1;
   FILE *file;
   Pcre_rule_limits current_limits;
   char pcre_string[128];
   char line[256];
   int line_matches;
   Pcre_type_rule current_rule;
   int matcher_num,client,server;
   const char *pcre_error;
   int error_offset;
   int i;

   file=fopen(filename,"r");
   if (NULL==file){
      fprintf(stderr,"Pcre matcher: cannot open rules file %s\n",filename);
      return -1;
   }
   // since we have pcre, better pcre than fscanf?
   while(fgets(line, 256, file) != NULL){
      line_matches=sscanf(line,"%d %d %d %127s %u %u %u %u %u",
                    &matcher_num,&client,&server,pcre_string,
                    &(current_rule.limit.proto),
                    &(current_rule.limit.min_packets),
                    &(current_rule.limit.max_packets),
                    &(current_rule.limit.min_bytes),
                    &(current_rule.limit.max_bytes)
                    );
      if(9==line_matches){
           fprintf(stdout,"Pcre matcher, loaded : %s\n", pcre_string);
           current_rule.client=client;
           current_rule.server=server;  
           current_rule.re=pcre_compile(
  					pcre_string,          /* the pattern */
  					0,                    /* default options */
  					&pcre_error,          /* for error message */
 					&error_offset,        /* for error offset */
 					NULL);                /* use default character tables */
           //post compile
           if(NULL==current_rule.re){
               fprintf(stderr,"PCRE compilation failed at on %s\n offset %d: %s\n", pcre_string,error_offset, pcre_error);
               return -1;
           }
           // now analyze
           current_rule.pe=pcre_study(current_rule.re,0,&pcre_error);
           if(NULL==current_rule.pe){
               fprintf(stderr,"No extra during study\n");
           }
           //finish loader
           if(matcher_num>=MAX_PCRE_MATCH_TYPES){
              fprintf(stderr,"Pcre matcher: invalid line in file, too high matcher id: %s\n",line);
              return -1;
           }
           if(matcher[matcher_num].num_rules>=MAX_PCRE_RULES_PER_TYPE){
              fprintf(stderr,"Pcre matcher: invalid line in file, too many rules id: %s\n",line);
              return -1;
           }  

           // adjust rule           
           if(current_rule.limit.min_bytes<matcher[matcher_num].rule[matcher[matcher_num].num_rules].limit.min_bytes){
              matcher[matcher_num].rule[matcher[matcher_num].num_rules].limit.min_bytes=current_rule.limit.min_bytes;
           }
           if(current_rule.limit.max_bytes>matcher[matcher_num].rule[matcher[matcher_num].num_rules].limit.max_bytes){
              matcher[matcher_num].rule[matcher[matcher_num].num_rules].limit.max_bytes=current_rule.limit.max_bytes;
           }
           if(current_rule.limit.min_packets<matcher[matcher_num].rule[matcher[matcher_num].num_rules].limit.min_packets){
              matcher[matcher_num].rule[matcher[matcher_num].num_rules].limit.min_packets=current_rule.limit.min_packets;
           }
           if(current_rule.limit.max_packets>matcher[matcher_num].rule[matcher[matcher_num].num_rules].limit.max_packets){
              matcher[matcher_num].rule[matcher[matcher_num].num_rules].limit.max_packets=current_rule.limit.max_packets;
           }
           matcher[matcher_num].rule[matcher[matcher_num].num_rules].client=client;
           matcher[matcher_num].rule[matcher[matcher_num].num_rules].server=server;
           matcher[matcher_num].rule[matcher[matcher_num].num_rules].re=current_rule.re;
           matcher[matcher_num].rule[matcher[matcher_num].num_rules].pe=current_rule.pe;
           matcher[matcher_num].num_rules++;
           matcher[matcher_num].initial_val=(matcher[matcher_num].initial_val<<1) | 0x1;
           
           //adjust matcher
           if(current_rule.limit.min_bytes<matcher[matcher_num].limit.min_bytes){
              matcher[matcher_num].limit.min_bytes=current_rule.limit.min_bytes;
           }
           if(current_rule.limit.max_bytes>matcher[matcher_num].limit.max_bytes){
              matcher[matcher_num].limit.max_bytes=current_rule.limit.max_bytes;
           }
           if(current_rule.limit.min_packets<matcher[matcher_num].limit.min_packets){
              matcher[matcher_num].limit.min_packets=current_rule.limit.min_packets;
           }
           if(current_rule.limit.max_packets>matcher[matcher_num].limit.max_packets){
              matcher[matcher_num].limit.max_packets=current_rule.limit.max_packets;
           }


           //adjust class val
          if(current_rule.limit.min_bytes<limit.min_bytes){
              limit.min_bytes=current_rule.limit.min_bytes;
           }
           if(current_rule.limit.max_bytes>limit.max_bytes){
              limit.max_bytes=current_rule.limit.max_bytes;
           }
           if(current_rule.limit.min_packets<limit.min_packets){
              limit.min_packets=current_rule.limit.min_packets;
           }
           if(current_rule.limit.max_packets>limit.max_packets){
              limit.max_packets=current_rule.limit.max_packets;
           }


      }
   }
#ifdef VERBOSE
  fprintf(stderr,"pcre: configuraton global : min_bytes=%d,max_bytes=%d min_packets=%d, max_packets=%d\n",
                                                limit.min_bytes,limit.max_bytes,
                                                  limit.min_packets,limit.max_packets);
#endif
   for(i=0;i<MAX_PCRE_MATCH_TYPES;i++){
       matcher[i].initial_val= ~ matcher[i].initial_val;
       if(0!=matcher[i].num_rules){
           matcher[i].initial_val|=PCRE_POSSIBLE_MATCH;
       }
       default_flow_state.state[i]=matcher[i].initial_val;  
       fprintf(stderr,"pcre: configuraton matcher[%d] : min_bytes=%d,max_bytes=%d min_packets=%d, max_packets=%d initial_val=%x\n",
                                                i,matcher[i].limit.min_bytes,matcher[i].limit.max_bytes,
                                                  matcher[i].limit.min_packets,matcher[i].limit.max_packets,
                                                  matcher[i].initial_val);
   }

   fclose(file); 
   rvalue=0;
   return rvalue;
}

int Pcre_Flow_Tagger::internal_collector(){
    //this is the body of the sebek processing section
   int rvalue;
   Copy_Packet *in_packet;
   list<Copy_Packet>::iterator packet_it;
   int list_size=0;
   int last_warn_size=0;
   struct timespec current_delay=delay;

   while(1){
         // simple loop:
        //   1. sem wait
        //      1b. check if done while waiting(very important)!
        //   2. get handle of  localbuff (critical section). and update delay
        //          a. mutex lock
        //          b. grab ptr
        //          c. mutex unlock
        //   3. handle_sebek_packet
        //   3. delete data // second critical section (pop);


        //step1
        rvalue=0;
        do{
          rvalue=sem_wait(&queue_sem);
          if((0!=rvalue) && (EINTR!=rvalue)){
              perror("hflow_sebek: error on sem_wat"); exit(1);
            };
          }while ((rvalue!=0) && (rvalue!=EINTR));

        if (true==input_done && 1>=list_size){goto normal_end;}

        //step2 get handle
        rvalue=pthread_mutex_lock(&in_queue_mutex);
        if(0!=rvalue){perror("hflow pcre: error on mutex lock, collector"); exit(1);};
        in_packet=&(*packet_queue.begin());
        delay=current_delay;

        rvalue=pthread_mutex_unlock(&in_queue_mutex);
        if(0!=rvalue){perror("hflow pcre: error on mutex unlock, collector"); exit(1);};

        //setep 3 do db_insert
        //do_version3(in_packet);
        #ifdef VERBOSE
        fprintf(stderr,".");
        #endif

        ///step 4 delete
        rvalue=pthread_mutex_lock(&in_queue_mutex);
        if(0!=rvalue){perror("hflow pcre: error on mutex lock, collector"); exit(1);};
        packet_queue.pop_front();
        list_size=packet_queue.size();
        rvalue=pthread_mutex_unlock(&in_queue_mutex);
        if(0!=rvalue){perror("hflow pcre: error on mutex unlock, collector"); exit(1);};

        if (list_size>10){
           if(list_size>=last_warn_size){
              #ifdef VERBOSE
              cout <<"hflow pcre warning: large list size, size=" <<list_size<<endl;
              #endif
              last_warn_size=list_size;
              current_delay.tv_nsec=5000000;
           }
        }
        else{last_warn_size=0; current_delay.tv_nsec=0;}

    }
normal_end:
  sem_post(&done_sem);
  pthread_exit(NULL);
  return 0;
}





#endif
