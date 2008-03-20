// (C) 2006 The Trustees of Indiana University.  All rights reserved.
//
// Copyright (C) 2001/2005 The Honeynet Project.
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

#ifndef HFLOW_SEBEK_BLOCK_HPP
#define HFLOW_SEBEK_BLOCK_HPP


/*
  Hflow_sebek_block.. replaces sebekd and portions of hflowd.pl
   is threaded as not know a priori how long a db operation can take
   so we need to separate the processing of data
   this module is also very memory intensive, so use with care

   this hpp requires: -lpthread, -ldl ,-ldbi  !!

*/



#include "element.h"
#include <pcap.h>
#include <map>
#include <list>
#include <iostream>
#include <string.h>
#include <dbi/dbi.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>
#include <vector>

#include <semaphore.h>
#include <signal.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#define MAX_HONEYPOTS 4
#define MAX_PROCESS_ID 32769
#define COMMAND_CACHE_SIZE_LIMIT 512
#define SBK_MAX_QUERY_SIZE 1000

using namespace std; 

/*Sebek Struct definitions */
struct sebek_v3_header{
  u_int32_t  magic       __attribute__((packed)) ;
  u_int16_t  version     __attribute__((packed)) ;

  u_int16_t  type        __attribute__((packed)) ;
  //--- 0  read
  //--- 1  write
  //--- 2  socket
  //--- 3  open

  u_int32_t  counter     __attribute__((packed)) ;
  u_int32_t  time_sec    __attribute__((packed)) ;
  u_int32_t  time_usec   __attribute__((packed)) ;
  u_int32_t  parent_pid  __attribute__((packed)) ;
  u_int32_t  pid         __attribute__((packed)) ;
  u_int32_t  uid         __attribute__((packed)) ;
  u_int32_t  fd          __attribute__((packed)) ;
  u_int32_t  inode       __attribute__((packed)) ;
  char com[12]    	 __attribute__((packed)) ;
  u_int32_t  length      __attribute__((packed)) ;
};

struct sebek_v3_socket_record{
  u_int32_t  dip        __attribute__((packed));
  u_int16_t  dport      __attribute__((packed));
  u_int32_t  sip        __attribute__((packed));
  u_int16_t  sport      __attribute__((packed));
  u_int16_t  call       __attribute__((packed));
  u_int8_t   proto      __attribute__((packed));
};

///////////////////*helper classes definitions*/
class remote_process_info{
 public:
   unsigned short ppid;
   unsigned short low_last_pcap_sec;
   unsigned int   db_id;
   unsigned int   command_id;
};

class Stand_Alone_Packet : public Tagged_IP_Packet{
 public:
  int packet_type;
  struct pcap_pkthdr true_pcap_hdr;
  u_char pkt_data[MAX_PACKET_PAYLOAD_LENGTH];
  int fill_from_packet(const Tagged_IP_Packet *in_packet){
      ip_header_offset=in_packet-> ip_header_offset;
      transport_offset=in_packet-> transport_offset;
      true_pcap_hdr=*(in_packet->pcap_hdr);
      memcpy(pkt_data,in_packet->data,in_packet->pcap_hdr->len);
      return 0;
      };
  Stand_Alone_Packet(){
      memset(&true_pcap_hdr,0x00,sizeof(struct pcap_pkthdr));
      pcap_hdr=&true_pcap_hdr;
      data=pkt_data;
      };
  Stand_Alone_Packet(const Tagged_IP_Packet &build_from){
      fill_from_packet(&build_from);
      //Stand_Alone_Packet();
      pcap_hdr=&true_pcap_hdr;
      data=pkt_data;

      };
  Stand_Alone_Packet(const Stand_Alone_Packet &build_from){
      // fill_from_packet(&source);
      if(this !=&build_from){
         ip_header_offset=build_from.ip_header_offset;
         transport_offset=build_from.transport_offset;
         memcpy(&true_pcap_hdr,&build_from.true_pcap_hdr,sizeof(struct pcap_pkthdr));
         memcpy(pkt_data,build_from.pkt_data,build_from.true_pcap_hdr.len);
         pcap_hdr=&true_pcap_hdr;
         data=pkt_data;

         //Stand_Alone_Packet();
         }
      };

  Stand_Alone_Packet& operator=(const Tagged_IP_Packet &source){
      if(this!=&source){
        fill_from_packet(&source);
        //Stand_Alone_Packet();
        pcap_hdr=&true_pcap_hdr;
        data=pkt_data;

        }
      return *this;
      };
  Stand_Alone_Packet& operator=(const Stand_Alone_Packet &source){
      if(this!=&source){

        // fill_from_packet(&source);
        ip_header_offset=source.ip_header_offset;
        transport_offset=source.transport_offset;
        memcpy(&true_pcap_hdr,&source.true_pcap_hdr,sizeof(struct pcap_pkthdr));
        memcpy(pkt_data,source.pkt_data,source.true_pcap_hdr.len);
        pcap_hdr=&true_pcap_hdr;
        data=pkt_data;

       
        }
      return *this;
      };


};

//////---------------------------------------------------------
// this is just a helper class to allow the internal mapping of
// commands in STL like containers.
class Sortable_Command{
 public:
   char name[16];
   Sortable_Command & operator=(const Sortable_Command &rhs);
   Sortable_Command(){memset(name,0x00,16);} 

};

/*const Sortable_Command & Sortable_Command::operator=(const Sortable_Command &rhs) {
  if (this == &rhs)      
       return *this;        
  strncpy(this->name,rhs->name,12);
  return *this;
}*/
bool operator < (const Sortable_Command &left,const Sortable_Command &right){
    if (0<strncmp(left.name,right.name,12))
          return true;
    else  
          return false;
   }
bool operator == (const Sortable_Command &left,const Sortable_Command &right){
    if (0==strncmp(left.name,right.name,12))
          return true;
    else
          return false;
   }
////---------

//////////////////Class definition
class Hflow_Sebek_Block: public Processing_Block{
  private:
    unsigned int sensor_id;
    remote_process_info process_db[MAX_HONEYPOTS][MAX_PROCESS_ID];
    unsigned int ip_to_localid[MAX_HONEYPOTS]; //need better struct
    unsigned short hpots_used;
    list <Stand_Alone_Packet> sebek_packet_queue;
    pthread_t sebek_processing_thread;
    pthread_mutex_t in_queue_mutex;
    sem_t queue_sem;
    sem_t done_sem;
    volatile bool input_done;
    dbi_conn conn;
    u_int16_t sebek_dst_port;
    u_int16_t sebek_src_port; 
    map <Sortable_Command,unsigned int> name2command_id_cache;
    unsigned int current_command_cache_size; 
    int initialize_internal_vals();
    bool is_sebek_packet(const Tagged_IP_Packet *in_packet);
    struct timespec delay;
    unsigned int last_process_db_id;
    int do_sys_socket_v3(unsigned int process_id,const sebek_v3_socket_record *in_record,const struct sebek_v3_header *sbk_header,unsigned int pcap_sec,char *out_query);


  public:
    inline int entry_point(const Tagged_Element *in_packet){return entry_point((Tagged_IP_Packet *) in_packet);};
    int entry_point(const Tagged_IP_Packet *in_packet);
    int set_output_point(Processing_Block *out_block);
    int set_output_point(Processing_Block *,int out_index);
    int do_version3(const struct Tagged_IP_Packet *in_packet);
    int do_version3(const struct ip *ip_header,const struct sebek_v3_header *sbk_header,const unsigned int pcap_sec);
    int initialize(int numoutputs);
    int initialize(int in_numoutputs,char* dbtype, char* dbname, char* username,char *password);
    int initialize(int in_numoutputs,char* dbtype, char* dbname, char* username,char *password,unsigned int in_sensor_id);
    int internal_collector(); //this guy never returns...
    Hflow_Sebek_Block();
    ~Hflow_Sebek_Block();
    int set_dst_port(uint16_t port){sebek_dst_port=port; return 0;}
};
//next func, maybe static function better?
void *hflow_sebek_thread_func(void *inblock){
             Hflow_Sebek_Block *in_class;
             in_class=(Hflow_Sebek_Block *)inblock;
             in_class->internal_collector();
             return NULL;
};



////////Class implementation
Hflow_Sebek_Block::Hflow_Sebek_Block(){
   initialized=false;
   next_stage=NULL;
   num_outputs=0;
   sebek_dst_port=1101;
   sebek_src_port=1101;
   delay.tv_sec=0;
   delay.tv_nsec=0;
   hpots_used=0;
   last_process_db_id=0;
   input_done=false;
};


Hflow_Sebek_Block::~Hflow_Sebek_Block(){
   //int rvalue;
   //join the other thread!!!
   int rvalue;
   input_done=true;

   fprintf(stderr,"Sebek Block(%d): destroying sebek block\n",getpid());
   if(true==initialized){
       rvalue=sem_post(&queue_sem);
      //aug 23: 8:30am .. there is still a race condition....
      // maybe change implementation of end function..
       if(0!=rvalue){perror("hflow_sebek: error on queue post in destructor"); exit(1);};
       fprintf(stderr,"sebk block (t:%u) before pthread join(%u)\n",pthread_self(),sebek_processing_thread);
       //rvalue=sem_wait(&done_sem);
       pthread_join(sebek_processing_thread,NULL);
       fprintf(stderr,"hflow_sebek:after join\n");
       initialized=false;
       }
   fprintf(stderr,"sebek block destroyed\n");

};

int Hflow_Sebek_Block::initialize_internal_vals(){
   char query[SBK_MAX_QUERY_SIZE];
   dbi_result result;
   int rvalue;
   long temp;

   ///load the largest process_id
   snprintf(query,SBK_MAX_QUERY_SIZE-1,"SELECT process_id  FROM process  " 
                                       " WHERE sensor_id=%u order by process_id desc limit 1",
                                       sensor_id);
   result=dbi_conn_query(conn,query);
   if(!result){
         fprintf(stderr,"%s\n",query);
         perror("problem on query select process_id "); exit(1);
         }
   if(dbi_result_next_row(result)){
           //idnumber = dbi_result_get_uint(result, "id");
           //fullname = dbi_result_get_string(result, "name");
           //printf("%i. %s\n", idnumber, fullname);
           //fprintf(stderr,"GOT RESULT!!!\n");
           //fprintf(stderr,"names=%s",dbi_result_get_field_name(result,1));
           //temp=dbi_result_get_long_idx(result,3);
           temp=dbi_result_get_long(result, "process_id");
           fprintf(stderr,"temp=%u",temp);
           last_process_db_id=temp;
           //process_db[hpot_id][ntohl(sbk_header->parent_pid)].db_id=process_ppid_db_id;
           }
   rvalue=dbi_result_free(result);
  
   ///------------maybe also preload sebek stuff?


   //fprintf(stderr,"init: query='%s'\nlast process_db_id=%u\n",query,last_process_db_id);

   return 0;
}


int Hflow_Sebek_Block::initialize(int in_numoutputs){
   return initialize(in_numoutputs,"mysql","hflow","hflowdaemon","");
}

int Hflow_Sebek_Block::initialize(int in_numoutputs,char* dbtype, char* dbname, char* username,char *password){
  return initialize(in_numoutputs, dbtype, dbname, username,password,0);

}
int Hflow_Sebek_Block::initialize(int in_numoutputs,char* dbtype, char* dbname, char* username,char *password,unsigned int in_sensor_id)
{
  int i;
  int rvalue;

  sensor_id=in_sensor_id;
  // do db init
  if (false==dbi_initialized){
      rvalue=dbi_initialize(NULL);
      if (0>rvalue){
           //fprintf(stderr, "init-failted rvalue=%d\n",rvalue);
           perror("Sebek block: Error initializing dbi interface .. aborting\n");
           exit(1);
         }
      dbi_initialized=true;
      }
  conn=dbi_conn_new(dbtype);
  dbi_conn_set_option(conn,"host","localhost");
  dbi_conn_set_option(conn, "dbname", dbname);
  dbi_conn_set_option(conn, "username", username);
  dbi_conn_set_option(conn, "password", password);
  if(0>dbi_conn_connect(conn)){
      perror("failed to connect to database .. exiting\n");
      exit(1);
      }
  //update current image?
  rvalue=initialize_internal_vals();
  if(0!=rvalue){perror("cannot initialize vals..exiting\n");exit(1);} 
  
  //block init
  next_stage =new Processing_Block*[in_numoutputs];
  num_outputs=in_numoutputs;
  for(i=0;i<num_outputs;i++){
     next_stage[i]=NULL;   
  } 
  //initialize sh structs
  rvalue=pthread_mutex_init(&in_queue_mutex,NULL);
  if(0!=rvalue){perror("cannot initialize mutex in hflow_sebek"); exit(1);}

  rvalue=sem_init(&queue_sem,0, 0);
  if(-1==rvalue){perror("cannot initialize semaphore in hflow_sebek"); exit(1);}

  rvalue=sem_init(&done_sem,0, 0);
  if(-1==rvalue){perror("cannot initialize semaphore in hflow_sebek"); exit(1);}

 

  //create the new thread
  rvalue=pthread_create(&sebek_processing_thread,NULL,hflow_sebek_thread_func,(void*)this);
  if(0!=rvalue){perror("cannot create new thread in hflowsebek"); exit(1);};
  fprintf(stderr,"sebek block: new thread %u\n",sebek_processing_thread);

  //setup memory
  memset(process_db,0x00,MAX_HONEYPOTS*MAX_PROCESS_ID*sizeof(remote_process_info));

  initialized=true;
  valid_outputs=0;
  return 0; 
};


int Hflow_Sebek_Block::entry_point(const Tagged_IP_Packet *in_packet){
  int i;
  int rvalue=0;
  struct timespec local_delay;

  ///processs here:
   if(is_sebek_packet(in_packet)){
      //fprintf(stderr,"-");
     //copy packet....
     //classic push stuff into queue in a critial protected region
      rvalue=pthread_mutex_lock(&in_queue_mutex);
      if(0!=rvalue){perror("hflow_sebek: error on mutex lock, entry"); exit(1);};
      sebek_packet_queue.push_back(*in_packet);
      local_delay=delay;
      rvalue=pthread_mutex_unlock(&in_queue_mutex);
      if(0!=rvalue){perror("hflow_sebek: error on mutex unlock, entry"); exit(1);};
      //set up signal for interal thread.
      rvalue=sem_post(&queue_sem);
      if(0!=rvalue){perror("hflow_sebek: error on queue post, entry"); exit(1);};

      if((local_delay.tv_nsec!=0) && (false==false)){
//         rvalue=nanosleep(&delay,NULL);
         do{
             rvalue=nanosleep(&delay,NULL);
         }while(rvalue!=0 && EINTR==errno);

         if(0!=rvalue){perror("hflow_sebek: error on nanosleep, entry"); exit(1);};
      }
   }
  // call each valid output
  for(i=0;i<valid_outputs;i++){
     (next_stage[i])->entry_point(in_packet);
  }
  return rvalue;
}

int Hflow_Sebek_Block::set_output_point(Processing_Block *out_block){
   
  if (false==initialized){
     initialize(1);
  }
  next_stage[0]=out_block;
  if (valid_outputs<1){
     valid_outputs=1;
  };
  return 0;
}

////////
int Hflow_Sebek_Block::internal_collector(){
    //this is the body of the sebek processing section
   int rvalue;
   Stand_Alone_Packet *in_packet;
   list<Stand_Alone_Packet>::iterator packet_it;
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
          }while(rvalue!=0 && EINTR==errno);
        if(0!=rvalue){
           perror("hflow_sebek: error on sem_wat"); exit(1);
        };


/*

        do{
          rvalue=sem_wait(&queue_sem);
          if((0!=rvalue) && (EINTR!=errno)){
              perror("hflow_sebek: error on sem_wat"); exit(1);
            };
          }while ((rvalue!=0) && (errno!=EINTR));
*/

        if (true==input_done && 1>=list_size){goto normal_end;}

        //step2 get handle
        rvalue=pthread_mutex_lock(&in_queue_mutex);
        if(0!=rvalue){perror("hflow sebek: error on mutex lock, collector"); exit(1);};
        in_packet=&(*sebek_packet_queue.begin());
        delay=current_delay; 

        rvalue=pthread_mutex_unlock(&in_queue_mutex);
        if(0!=rvalue){perror("hflow_sebek: error on mutex unlock, collector"); exit(1);};

        //setep 3 do db_insert
        do_version3(in_packet);
        #ifdef VERBOSE
        fprintf(stderr,".");
        #endif

        ///step 4 delete
        rvalue=pthread_mutex_lock(&in_queue_mutex);
        if(0!=rvalue){perror("hflow_sebek: error on mutex lock, collector"); exit(1);};
        sebek_packet_queue.pop_front();
        list_size=sebek_packet_queue.size();
        rvalue=pthread_mutex_unlock(&in_queue_mutex);
        if(0!=rvalue){perror("hflow_sebek: error on mutex unlock, collector"); exit(1);};

        if (list_size>10){
           if(list_size>=last_warn_size){
              #ifdef VERBOSE
              cout <<"hflow_sebek warning: large list size, size=" <<list_size<<endl;
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

inline int Hflow_Sebek_Block::do_version3(const struct Tagged_IP_Packet *in_packet){
  //assumes packet was checked as sebek packet
  struct ip *ip_header;
  struct sebek_v3_header *sbk_header;

  ip_header=(struct ip*)(in_packet->data+in_packet->ip_header_offset);
  sbk_header=(struct sebek_v3_header *)(in_packet->data+in_packet->ip_header_offset+20+8);

  return do_version3(ip_header,sbk_header,in_packet->pcap_hdr->ts.tv_sec);  //do we need conversion?

}

int Hflow_Sebek_Block::do_version3(const struct ip *ip_header,const struct sebek_v3_header *sbk_header,const unsigned int pcap_sec){
  //extract header info
   // check for honeypot def... 
   //         create one if necessary and possible
   // check for process id
   // check for command name and load if necessary 


   struct sebek_v3_socket_record *sbk_socket;
   int i;
   int hpot_id=-1;
   char query[SBK_MAX_QUERY_SIZE];
   char open_name[128];
   u_char *sbk_data;
   char *read_ptr;
   char *open_ptr;
   int copy_size;
   unsigned int process_db_id=0;
   unsigned int process_ppid_db_id=0;
   dbi_result result;
   int rvalue;
   Sortable_Command scom;
   map<Sortable_Command,unsigned int>::iterator command_iter;
   static char *insert_into_process="INSERT INTO process"
                                   "(sensor_id,process_id,src_ip,time_min,time_max,"
                                   "pcap_time_min,pcap_time_max,pid) VALUES";

   //step 1------------------
   for(i=0;i<MAX_HONEYPOTS;i++){
       if(ip_to_localid[i]==ntohl(ip_header->ip_src.s_addr)){
            hpot_id=i;     
            i=MAX_HONEYPOTS;
       }
   }
      
   if (-1==hpot_id){
          //might need to add a new hpot
          if (hpots_used+1<MAX_HONEYPOTS){
              ip_to_localid[hpots_used]=ntohl(ip_header->ip_src.s_addr);
              hpot_id=hpots_used;
              hpots_used++;
          }
          else{
             fprintf(stderr,"WARN: need more honeypot space");
             exit(1);
          }
   }
   //step 2 actualy do some sebek stuff
   //fprintf(stderr,"/");
   //fprintf(stderr,"%u %u %u %u %s\n",ntohl(ip_header->ip_src.s_addr),ntohl(sbk_header->counter),
   //                                  ntohl(sbk_header->pid),ntohl(sbk_header->parent_pid),sbk_header->com);

   //--is same process? ppid match and db_id!=0
  
   //---is new process? dbid nonexistend or (ppid do not match and current!=1) 
   if((0==process_db[hpot_id][ntohl(sbk_header->pid)].db_id) ||
      (   (process_db[hpot_id][ntohl(sbk_header->pid)].ppid!=ntohl(sbk_header->parent_pid) ) &&
          (process_db[hpot_id][ntohl(sbk_header->pid)].ppid!=1) )){
     #ifdef VERBOSE
     fprintf(stderr,"N");
     #endif
     process_db_id=last_process_db_id+1;
     //--insert new process to db, with new localid
     snprintf(query,SBK_MAX_QUERY_SIZE-1,"%s (%u,%u,%u,%u,%u,  %u,%u,%u)",
                                        insert_into_process,
                                        sensor_id,process_db_id ,ntohl(ip_header->ip_src.s_addr),
                                        ntohl(sbk_header->time_sec) ,ntohl(sbk_header->time_sec),
                                        pcap_sec,pcap_sec,ntohl(sbk_header->pid) 
                                       );
     //fprintf(stderr,"%s\n",query);
     result=dbi_conn_query(conn,query);
     if(!result){
         fprintf(stderr,"%s\n",query);
         perror("problem on query insert new process"); exit(1);
         }
     rvalue=dbi_result_free(result);

     //----update the db_id in the local database
     process_db[hpot_id][ntohl(sbk_header->pid)].db_id=process_db_id;
     last_process_db_id=process_db_id;
     //also update other local db fields...
     process_db[hpot_id][ntohl(sbk_header->pid)].ppid= ntohl(sbk_header->parent_pid);
     process_db[hpot_id][ntohl(sbk_header->pid)].low_last_pcap_sec=(0xFFFF |pcap_sec);

     //--- insert also in the process tree 
     //-- try to find the parent process db id, 
     if(0==process_db[hpot_id][ntohl(sbk_header->parent_pid)].db_id){//ppid db_id unkown
        #ifdef VERBOSE
        fprintf(stderr,"P");
        #endif
        //try to find in database but only of recent        
        snprintf(query,SBK_MAX_QUERY_SIZE-1,"SELECT process_id FROM  process"
                                            " WHERE sensor_id=%u and pid=%u AND pcap_time_max+600>%u"
                                            " ORDER BY pcap_time_max DESC LIMIT 1",
                                             sensor_id,ntohl(sbk_header->parent_pid),pcap_sec);
        result=dbi_conn_query(conn,query);
        if(!result){
            fprintf(stderr,"%s\n",query);
            perror("problem on query select process_id "); exit(1);
            }
        if(dbi_result_next_row(result)) {
           //idnumber = dbi_result_get_uint(result, "id");
           //fullname = dbi_result_get_string(result, "name");
           //printf("%i. %s\n", idnumber, fullname);
           process_ppid_db_id=dbi_result_get_long(result, "process_id");
           process_db[hpot_id][ntohl(sbk_header->parent_pid)].db_id=process_ppid_db_id; 
           }

        rvalue=dbi_result_free(result);
        }
     else{
        process_ppid_db_id=process_db[hpot_id][ntohl(sbk_header->parent_pid)].db_id;    
        }
     //if there is a parentprocess db id then do an insert
     if(0!=process_ppid_db_id){ //do process tree insert
        snprintf(query,SBK_MAX_QUERY_SIZE-1,"INSERT INTO process_tree (sensor_id,child_process,parent_process) "
                                            " VALUES (%u,%u,%u)",
                                        sensor_id,process_db_id,process_ppid_db_id);
        result=dbi_conn_query(conn,query);
        if(!result)
            {perror("problem on query insert into process_tree"); exit(1);}
        rvalue=dbi_result_free(result);
        }
     //--nothing else to do for new processes 
     }
   else{//this is an old process...
       //update the endtime in the db... if needed..(again minimize transactions)
       if((pcap_sec | 0xFFFF)!= process_db[hpot_id][ntohl(sbk_header->pid)].low_last_pcap_sec){
           snprintf(query,SBK_MAX_QUERY_SIZE-1,"UPDATE process "
                                               " set pcap_time_max=%u, time_max=%u "
                                               " WHERE sensor_id=%u and process_id=%u",
                                                pcap_sec,ntohl(sbk_header->time_sec),
                                        sensor_id,process_db[hpot_id][ntohl(sbk_header->pid)].db_id);
           result=dbi_conn_query(conn,query);
           if(!result) {
               fprintf(stderr,"query='%s'\n",query);
               perror("problem on query,update process "); 
               exit(1);}
           rvalue=dbi_result_free(result);
          }
     }
   process_db_id=process_db[hpot_id][ntohl(sbk_header->pid)].db_id;
   //------check the command name.....
   // look in local cache...
   //     else search on db..
   //         else
   //            insert on db
   //             query db and insert into local cache...
   // if the command_id does not match.. insert do insert on process_to_com
   strncpy(scom.name,sbk_header->com,12);
   command_iter=name2command_id_cache.find(scom); 
   if(name2command_id_cache.end()==command_iter){
        snprintf(query,SBK_MAX_QUERY_SIZE-1,"SELECT command_id FROM  command"
                                            " WHERE sensor_id=%u AND name='%s'",
                                             sensor_id,scom.name);
        //the previous assumes no quotes on the name.....
        result=dbi_conn_query(conn,query);
        if(!result){
            fprintf(stderr,"%s\n",query);
            perror("problem on query select command "); exit(1);
            }
        if(dbi_result_next_row(result)) {
           name2command_id_cache[scom]=dbi_result_get_long(result, "command_id");
           }
        else{// not found
            rvalue=dbi_result_free(result);
            //---do an insert...
            snprintf(query,SBK_MAX_QUERY_SIZE-1,"INSERT INTO  command (sensor_id,name ) "
                                            " VALUES (%u,'%s')",
                                             sensor_id,scom.name);
            result=dbi_conn_query(conn,query);
            if(!result){
               fprintf(stderr,"%s\n",query);
               perror("problem on insert new command name "); exit(1);
               }
            rvalue=dbi_result_free(result);

            // and a select..again
            snprintf(query,SBK_MAX_QUERY_SIZE-1,"SELECT command_id FROM  command"
                                            " WHERE sensor_id=%u AND name='%s'",
                                             sensor_id,scom.name);
            result=dbi_conn_query(conn,query);
            if(!result){
               fprintf(stderr,"%s\n",query);
               perror("problem on insert new command name "); exit(1);
               }
            //---and update local
            if(dbi_result_next_row(result)) {
               name2command_id_cache[scom]=dbi_result_get_long(result, "command_id");
               }
            else{
               perror("cannot find inserted name\n"); exit(1);
               }
           }
        rvalue=dbi_result_free(result);

      }
   //small assertion for debugging only (find MUST find something!)
   command_iter=name2command_id_cache.find(scom);
   if(name2command_id_cache.end()==command_iter){perror("cannot find local command!!\n");exit(1);}

   if(name2command_id_cache[scom]!=process_db[hpot_id][ntohl(sbk_header->pid)].command_id){
       //insert into process_to_com
       //update local
        snprintf(query,SBK_MAX_QUERY_SIZE-1,"INSERT IGNORE INTO  process_to_com (sensor_id,process_id,command_id ) "
                                            " VALUES (%u,%u,'%u')",
                                             sensor_id, process_db_id,name2command_id_cache[scom]);
        result=dbi_conn_query(conn,query);
        if(!result){
               fprintf(stderr,"%s\n",query);
               perror("problem on insert new process_to_com "); exit(1);
        }
       rvalue=dbi_result_free(result);

       process_db[hpot_id][ntohl(sbk_header->pid)].command_id=name2command_id_cache[scom];

   }  
   //--- now we switch on the sebek type...
   // sys read-- do nothing.. 
   // sys_open-- insert into db
   sbk_data=((u_char*) sbk_header)+sizeof(struct sebek_v3_header);
   switch(ntohs(sbk_header->type)){
       case 0: //sys_read
               memset(open_name,0x00,128);//
               copy_size=ntohl(sbk_header->length);
               if(copy_size>(60-1)){copy_size=60-1;};
               read_ptr=(char *)sbk_data;
               open_ptr=open_name;
               for(i=0;i<copy_size;i++){
                  sprintf(open_ptr,"%02X",*read_ptr);
                  open_ptr+=2;
                  read_ptr++;
               }
               //fprintf(stderr,"INS='%s'\n",open_name);
               snprintf(query,SBK_MAX_QUERY_SIZE-1,"INSERT DELAYED INTO sys_read "
                                                   "(sensor_id,process_id,uid,pcap_time, "
                                                   "time,counter,filed,inode,length,data) "
                                                   "VALUES (%u,%u,%u,%u,  %u,%u,%u,%u,%u,x'%s')",
                                                   sensor_id,process_db_id,ntohl(sbk_header->uid),pcap_sec,
                                                   ntohl(sbk_header->time_sec),ntohl(sbk_header->counter),
                                                       ntohl(sbk_header->fd),ntohl(sbk_header->inode),ntohl(sbk_header->length),
                                                       open_name );
               rvalue=1;
               break;
       case 1: //write is not enabled!!(we should do something tough)
               rvalue=0;
               break;
       case 2: //sys_socket
               sbk_socket= (sebek_v3_socket_record *)(((u_char*) sbk_header)+sizeof(struct sebek_v3_header));
               rvalue=do_sys_socket_v3(process_db_id,sbk_socket,sbk_header, pcap_sec,query); 
               break;
       case 3: //sys open
               memset(open_name,0x00,128);
               copy_size=ntohl(sbk_header->length);
               if(copy_size>(128-1)){copy_size=128-1;};            
               strncpy(open_name,(char *)sbk_data,copy_size);
               snprintf(query,SBK_MAX_QUERY_SIZE-1,"INSERT DELAYED INTO sys_open "
                                                   "(sensor_id,process_id,uid,pcap_time, "
                                                   "time,counter,filed,inode,length,filename) "
                                                   "VALUES (%u,%u,%u,%u,  %u,%u,%u,%u,%u,'%s')",
                                                   sensor_id,process_db_id,ntohl(sbk_header->uid),pcap_sec,
                                                   ntohl(sbk_header->time_sec),ntohl(sbk_header->counter),
                                                       ntohl(sbk_header->fd),ntohl(sbk_header->inode),ntohl(sbk_header->length),
                                                       open_name );
               //fprintf(stderr,"%s\n",query);
               rvalue=1;
               break;
       default:
              rvalue=0;
           //do nothing;
          break;
   }  
   //do query!!!
   if(1==rvalue){
       result=dbi_conn_query(conn,query);
       if(!result){
           fprintf(stderr,"%s\n",query);
           perror("problem on insert new sys_* "); exit(1);
           }
       rvalue=dbi_result_free(result);
       }

   return 0;
}

int Hflow_Sebek_Block::do_sys_socket_v3(unsigned int process_id,const sebek_v3_socket_record *in_record,const struct sebek_v3_header *sbk_header,unsigned int pcap_sec,char *out_query){
   //find the flow...
   //once found do update
   //----
   //this function should interact with the current flows to optimize the search
   //--
   int iterations=0;
   char query[SBK_MAX_QUERY_SIZE];
   dbi_result result;
   int rvalue; 
   unsigned int flow_id=0;
   struct timespec delay;

   do{
      //I should actually make the query depending on the sycall number....
       snprintf(query,SBK_MAX_QUERY_SIZE-1,"SELECT flow_id,GREATEST(src_end_sec,dst_end_sec) as etime FROM flow "
                                         "WHERE sensor_id=%u AND ip_proto=%u AND src_start_sec<=%u AND "
                                             "(  (src_ip=%u AND dst_ip=%u AND " 
                                                "src_port=%u AND dst_port=%u)"
                                             "OR (src_ip=%u AND dst_ip=%u AND "
                                                "src_port=%u and dst_port=%u)) "
                                         "HAVING etime>=%u "
                                         "ORDER BY src_start_sec limit 1",
                                          sensor_id,in_record->proto,pcap_sec,
                                          ntohl(in_record->sip),ntohl(in_record->dip),ntohs(in_record->sport),ntohs(in_record->dport),
                                          ntohl(in_record->dip),ntohl(in_record->sip),ntohs(in_record->dport),ntohs(in_record->sport)
                                          ,pcap_sec );

        result=dbi_conn_query(conn,query);
        if(!result){
           fprintf(stderr,"%s\n",query);
           perror("problem on insert new command name "); exit(1);
            }
            //---and update local
        if(dbi_result_next_row(result)) {
               flow_id=dbi_result_get_long(result, "flow_id");
            }
        else{
            //was not found,sleep for a while
            // this is suboptimal,.. yes..... 
            // need to add dynamically way to change this...
            delay.tv_sec=0;
            delay.tv_nsec=2000000;
            //rvalue=nanosleep(&delay,NULL);
            do{
               rvalue=nanosleep(&delay,NULL);
            }while(rvalue!=0 && EINTR==errno);



            if(0!=rvalue) { perror("Sebek_socket: error on nanosleep\n"); exit(1);};
            }
        rvalue=dbi_result_free(result);   
        iterations++;
       //if some condition then wait
     }while(iterations<2);
   #ifdef VERBOSE
   fprintf(stderr,"sebek socket iterations=%d\n",iterations);
   #endif
   if(0==flow_id){
      #ifdef VERBOSE
      fprintf(stderr,"query='%s'",query);
      perror("Sebek_socket: unable tofind "); //exit(1);
      #endif
      return 0;
      }
   //now do the insert...
   snprintf(out_query,SBK_MAX_QUERY_SIZE-1,"INSERT DELAYED INTO sys_socket "
                                       "(sensor_id,process_id,pcap_time,time,uid,"
                                        "counter,filed,inode,flow_id,`call`)"
                                        "VALUES (%u,%u,%u,%u,%u,  %u,%u,%u,%u,%u)",
                                         sensor_id,process_id,pcap_sec,
                                           ntohl(sbk_header->time_sec),ntohl(sbk_header->uid),
                                         ntohl(sbk_header->counter),ntohl(sbk_header->fd),
                                           ntohl(sbk_header->inode), flow_id,ntohs(in_record->call));

  
   result=dbi_conn_query(conn,query);
   if(!result){
       fprintf(stderr,"%s\n",query);
       perror("problem on insert new sys_socket name "); exit(1);
       } 
   rvalue=dbi_result_free(result);
  
   
   return 1;
}


/*
int do_low_pid(unsigned int hpot_id, unsigned int pid,struct sebek_v3_header *sbk_header){

}
*/

bool Hflow_Sebek_Block::is_sebek_packet(const Tagged_IP_Packet *in_packet){
  struct ip *ip_header;
  struct udphdr *udp_header;
  struct sebek_v3_header *sbk_header;
  //const int sbk_header_size=56;

  //--start decoding
  ip_header=(struct ip*)(in_packet->data+in_packet->ip_header_offset);
  //a sebek packet has no options... so
  if((ip_header->ip_hl!=5) ||
     (ip_header->ip_v!=4)  ||
     (ip_header->ip_p!=17) ||
     (in_packet->pcap_hdr->caplen-in_packet->ip_header_offset<20+8+sizeof(struct sebek_v3_header) )){
      return false;
  }
  //assert ports
  udp_header=(struct udphdr*)(in_packet->data+in_packet->ip_header_offset+20);
  if(sebek_dst_port!=ntohs(udp_header->dest) || sebek_src_port!=ntohs(udp_header->source)){
    return false;
  }
  //sbk_header
  sbk_header=(struct sebek_v3_header *)(in_packet->data+in_packet->ip_header_offset+20+8);
  if(3!=ntohs(sbk_header->version)) {
    return false;
   }
   return true;

}
#endif
