// (C) 2006 The Trustees of Indiana University.  All rights reserved.
//
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
//         (with sections from snort 2.4.5)



#ifndef SNORT_BLOCK_HPP
#define SNORT_BLOCK_HPP

#include "element.h"
#include <pcap.h>
#include <map>
#include <list>
#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>

#include <dbi/dbi.h>
#include "pcap_outfile_block.hpp"
#include "l2_helpers.hpp"
#include "active_ipv4_flow_db.hpp"

using namespace std;
//local defines
#define SNORT_MAX_QUERY_LENGTH 1024
#define SNORT_MAX_OUTPUT_LINE_LENGTH 128
#define SNORT_MAX_FIFONAME_LENGTH 128

///snort structs and defs
#define SNORT_MAGIC     0xa1b2c3d4
#define ALERT_MAGIC     0xDEAD4137  /* alert magic, just accept it */
#define LOG_MAGIC       0xDEAD1080  /* log magic, what's 31337-speak for G? */



typedef struct _Event
{
    u_int32_t sig_generator;   /* which part of snort generated the alert? */
    u_int32_t sig_id;          /* sig id for this generator */
    u_int32_t sig_rev;         /* sig revision for this id */
    u_int32_t classification;  /* event classification */
    u_int32_t priority;        /* event priority */
    u_int32_t event_id;        /* event ID */
    u_int32_t event_reference; /* reference to other events that have gone off,
                                * such as in the case of tagged packets...
                                */
    //struct timeval ref_time;   /* reference time for the event reference */
    struct portable_timeval ref_time;

    /* Don't add to this structure because this is the serialized data
     * struct for unified logging.
     */
} Event;

typedef struct _SnortPktHeader  //this is just like a pcap_header
{
    //struct timeval ts;     /* packet timestamp */
    struct portable_timeval ts;
    u_int32_t caplen;      /* packet capture length */
    u_int32_t pktlen;      /* packet "real" length */
} SnortPktHeader;


typedef struct _UnifiedLogFileHeader
{
    u_int32_t magic;
    u_int16_t version_major;
    u_int16_t version_minor;
    u_int32_t timezone;
    u_int32_t sigfigs;
    u_int32_t snaplen;
    u_int32_t linktype;
} UnifiedLogFileHeader;


typedef struct _UnifiedLog
{
    Event event;
    u_int32_t flags;       /* bitmap for interesting flags */
    SnortPktHeader pkth;   /* SnortPktHeader schtuff */
} UnifiedLog;


/// a small helper
int print_snort_event(Event *event){
  return fprintf(stderr, "Event: sig_gen=%u sig_id=%u, sig_class=%u, event_id=%u\n",event->sig_generator,event->sig_id,event->classification,event->event_id);
}

///////////////////////

//////////////////Class definition
class Snort_Block: public Processing_Block{
  private:
    int pipe_fd[2];
    char fifoname[SNORT_MAX_FIFONAME_LENGTH];
    pid_t child_pid;
    int read_fifo_fd;
    pthread_t collector_thread;
    Pcap_Outfile_Block pcap_block; //code reuse   
    volatile bool input_done; 
    int snort_out_read_fd;
    int snort_out_fd; 
    dbi_conn conn;
    unsigned int sensor_id;
    char *conf_dir;
    char *log_dir;

  public:
    inline int entry_point(const Tagged_Element *in_packet){return entry_point((Tagged_IP_Packet *) in_packet);};
    int entry_point(const Tagged_IP_Packet *in_packet);
    int set_output_point(Processing_Block *out_block);
    int set_output_point(Processing_Block *,int out_index);
    int initialize(int numoutputs);
    int initialize(int in_numoutputs,  char* dbtype, char* dbname, char* username,char *password);
    int initialize(int in_numoutputs,  char* dbtype, char* dbname, char* username,char *password,unsigned int in_sensor_id);
    int internal_collector();//this guy never returns
    Snort_Block();
    ~Snort_Block();
   int set_log_dir(char *in){log_dir=in;return 0;}
};

void *snort_block_thread_func(void *inblock){
              Snort_Block *in_class;
              in_class=(Snort_Block *)inblock;
              in_class->internal_collector();
             return NULL;
}

////////Class implementation
Snort_Block::Snort_Block(){
   initialized=false;
   input_done=false;
   next_stage=NULL;
   num_outputs=0;
   conf_dir=NULL;
   log_dir=NULL;
   snprintf(fifoname,SNORT_MAX_FIFONAME_LENGTH-1,"/var/lib/hflow/snort.log");
   //snprintf(fifoname,SNORT_MAX_FIFONAME_LENGTH-1,"/tmp/snort-cam.log");
   sensor_id=0;
};

Snort_Block::~Snort_Block(){
  int rvalue;
  int status;
  char *localfifoname="/tmp/snort-cam.log";
  fprintf(stderr,"snort block start desstructor\n");
  if (true==initialized){
     close(pipe_fd[1]);
     sleep(1);
     input_done=true;
     //signal child
     fprintf(stderr,"Snort block (%d): about to send kill to %d\n",getpid(),child_pid);
     rvalue=kill(child_pid,SIGTERM);
     //sleep(1);
     //wait
     fprintf(stderr, "sigkill sent\n");
     rvalue=waitpid(child_pid,&status,0);
     fprintf(stderr, "waitpid returned\n");
     //forget about joining for now..
     rvalue=pthread_join(collector_thread,NULL);
     if(0!=rvalue){perror("Snort_block:error on pthread_join:");};
     
     //delete the fifo?
     rvalue=unlink(localfifoname);
     if(0!=rvalue){
            perror("Snort block: destructor delete of old fifo failed\n");
            }
     }
  fprintf(stderr,"snort block destroyed\n");
}


int Snort_Block::initialize(int in_numoutputs){
   return initialize(in_numoutputs,"mysql","hflow","hflowdaemon","");
}

int Snort_Block::initialize(int in_numoutputs,  char* dbtype, char* dbname, char* username,char *password){
   return initialize(in_numoutputs, dbtype, dbname,username,password,0);
}


int Snort_Block::initialize(int in_numoutputs,  char* dbtype, char* dbname, char* username,char *password, unsigned int in_sensor_id){
  int i;
  int rvalue;
  mode_t default_mode=(S_IRUSR | S_IWUSR | S_IRGRP|S_IROTH );
  char *local_fifoname="/tmp/snort-cam.log"; 
  char full_log_name[SNORT_MAX_OUTPUT_LINE_LENGTH];
  char full_conf_name[SNORT_MAX_OUTPUT_LINE_LENGTH];
  FILE *snort_output_stream;
  char file_line[SNORT_MAX_OUTPUT_LINE_LENGTH];  
  bool snort_proc_initialization_complete=false; 
  struct timespec delay;

  fprintf(stderr,"start of snort block_init\n");
  sensor_id=in_sensor_id;


  //do db init.....
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


  //create blocks.....
  next_stage =new Processing_Block*[in_numoutputs];
  num_outputs=in_numoutputs;
  for(i=0;i<num_outputs;i++){
     next_stage[i]=NULL;   
  }  

  //create new outputfifo
  rvalue=mkfifo(local_fifoname,default_mode);
  if(0!=rvalue){
     if (EEXIST==errno){
        fprintf(stderr,"snort_block:fifo exists attempting to delete\n");
        //delete and recreate
        rvalue=unlink(local_fifoname);
        if(0!=rvalue){
            perror("Snort block: delete of old fifo failed:");exit(1);
            }
        fprintf(stderr,"snort_block: successful deletion\n");
        rvalue=mkfifo(local_fifoname,default_mode);
        if (0!=rvalue){
             perror("Snort block: replace: Cannot make fifo:");exit(1);
             }
        }
     else{
        perror("Snort block: Cannot make fifo:");exit(1);
        }
  }
  //create in_packet pipe
  rvalue=pipe(pipe_fd);
  if(0!=rvalue){perror("Snort block: Cannot make pipe:");exit(1);} 
  fprintf(stderr,"snort_block: success creating pipe\n");

 //create the snort outdatafile
  if(NULL==log_dir){
     snprintf(&full_log_name[0],SNORT_MAX_OUTPUT_LINE_LENGTH-1,"snort_out.txt");
  }
  else{
     snprintf(&full_log_name[0],SNORT_MAX_OUTPUT_LINE_LENGTH-1,"%s/snort_out.txt",log_dir);
  }
  //snort_out_fd=open("snort_out.txt", O_WRONLY|O_CREAT |O_TRUNC,default_mode);
  snort_out_fd=open(&full_log_name[0], O_WRONLY|O_CREAT |O_TRUNC,default_mode);
  if(0>snort_out_fd){
      perror("Snort block: Cannot snort outfile:");
      fprintf(stderr,"'%s'\n",&full_log_name[0]);
      exit(1);
  }
 

  read_fifo_fd=0;

  //create new thread
  // rvalue=pthread_create(&collector_thread,NULL,snort_block_thread_func,(void*)this);
  // if(0!=rvalue){perror("cannot create new thread in dbinserter"); exit(1);};

  //fork
  child_pid=fork();
  if(-1==child_pid){perror("Snort block:Fork Failiure:");exit(1);}  
  //on fork do stuff
  if(0==child_pid){//this is the child
     //reduce prio
     //rvalue=nice(1);
     //if(0!=rvalue){perror("Snort block: child: Error on nice:");exit(1);}
     //do fd magic
     rvalue=close(0);
     if(0!=rvalue){perror("Snort block: child: Error closing stdin:");exit(1);}
     rvalue=dup(pipe_fd[0]);
     if(0!=rvalue){perror("Snort block: child: Dup failed:");exit(1);}

     rvalue=close(1);
     if(0!=rvalue){perror("Snort block: child: Error closing stdout:");exit(1);}
     rvalue=dup(snort_out_fd);
     if(1!=rvalue){perror("Snort block: child: stdout Dup failed:");exit(1);}
     rvalue=close(2);
     if(0!=rvalue){perror("Snort block: child: Error closing stderr:");exit(1);}
     rvalue=dup(snort_out_fd);
     if(2!=rvalue){perror("Snort block: child: stderr Dup failed:");exit(1);}
     


     rvalue=close(pipe_fd[1]);
     if(0!=rvalue){perror("Snort block: child: Error closig pipe wr:");exit(1);}
     //rvalue=dup2(pipe_fd[0],0);
     //rvalue=dup(pipe_fd[0]);
     //if(0!=rvalue){perror("Snort block: child: Dup failed:");exit(1);}
     //nice(4);

     rvalue=execlp("snort","snort","-r","-","-c","snort.conf","-l", "/var/lib/hflow/snort",(char *)NULL);
     //rvalue=execlp("snort","snort","-r","-","-c","snort.conf","-l", "/tmp/snortest",(char *)NULL);

     //rvalue=execlp("/tmp/snort-2.6.0/src/snort","/tmp/snort-2.6.0/src/snort","-r","-","-c","snort.conf","-l", "/tmp/snortest",NULL);
  
   //rvalue=execlp("/usr/sbin/tcpdump" ,"/usr/sbin/tcpdump" ,"-r", "-","-w","/tmp/snort-cam.log",NULL);
     if(0!=rvalue){perror("Snort block: child: Failed Snort exec:");exit(1);}
     //should not reach next line
     fprintf(stderr, "Snort aborted!!! , terminating ");
     exit(1);
     }
  else{//this is the parent
     rvalue=close(pipe_fd[0]);
     if(0!=rvalue){perror("Snort block: parent: Error closig pipe wr:");exit(1);}
     rvalue=close(snort_out_fd);
     if(0!=rvalue){perror("Snort block: parent: Error closig snort outfile");exit(1);}
    //exit(1);
     //rvalue=sleep(1);
     //write a tpdump header to the fifo
     }

  fprintf(stderr,"Snort block: fork section done!\n");
  //open fd for readfifo
  //read_fifo_fd=open(fifoname,O_RDONLY);
  //if(read_fifo_fd<0){perror("cannot open ffifo for read\n"); exit(1);};
  //fprintf(stderr,"open fifo done!\n");

  //create new thread
  rvalue=pthread_create(&collector_thread,NULL,snort_block_thread_func,(void*)this);
  if(0!=rvalue){perror("cannot create new thread in dbinserter"); exit(1);};



  ///initialize the pcap dumper
  //pcap_block.set_non_blocking();
  pcap_block.initialize_on_open_fd(pipe_fd[1]); 

  //initializaiton can only be checked out AFTER data starts flowing.. kind of dumb, but we will handle
  //now check if snort initialized correctly..
 //create an fd to read the snort outdatafile
  snort_out_read_fd=open(&full_log_name[0],O_RDONLY);
  if(0>snort_out_read_fd){perror("Snort block: Cannot reopen snort outfile for read:");exit(1);}
  //snort_output_stream=fopen("snort_out.txt","r");
  snort_output_stream=fdopen(snort_out_read_fd,"r");
  if(NULL==snort_output_stream){perror("Snort block: Cannot reopen snort outfile as stream:");exit(1);}
  //
  
  delay.tv_sec=3;
  delay.tv_nsec=700000000; //a 7/10 of a second should be plenty
  rvalue=nanosleep(&delay,NULL);
  if(0!=rvalue) {
     perror("Snort block: error on nanosleep\n");
     exit(1);
     };
  //sleep(2);
    
  while((fgets(file_line,SNORT_MAX_OUTPUT_LINE_LENGTH,snort_output_stream)!=NULL) && 
         (false== snort_proc_initialization_complete)         &&
         (i<10000) ){
       //if (NULL!=strstr(file_line,"Initialization Complete")){
       if (NULL!=strstr(file_line,"Reading network")){
           fprintf(stderr, "Snort proc initialization successful\n");
           snort_proc_initialization_complete=true;
           i=30000;
          } 
       //fprintf(stderr,".");
       //sleep(1);    
       i++;     
     }
  if(false==snort_proc_initialization_complete){
      perror("Snort block: failed to detect correct initialization of snort, aborting"); exit(1);
     }

  fclose(snort_output_stream);
  close(snort_out_read_fd);


  
  fprintf(stderr,"snort init section done!\n");
 
  initialized=true;
  valid_outputs=0;
  return 0; 
};


int Snort_Block::entry_point(const Tagged_IP_Packet *in_packet){
  //assumes it is initialized
  int i;
  //int rvalue;
  Tagged_Packet *pack_vect;

  //cout << "inpacket snort_block" <<endl;
  ///processs here
  
   //write to pipe_fd[1]...
  pack_vect=(Tagged_Packet *)in_packet;
  pcap_block.entry_point(in_packet);
  //rvalue=fsync(pipe_fd[1]);
  //cout << "flushed snort_block" <<endl;

   // call each valid output
  for(i=0;i<valid_outputs;i++){
     (next_stage[i])->entry_point(in_packet);
  }
  return 0;
}

int Snort_Block::set_output_point(Processing_Block *out_block){
   
  if (false==initialized){
     initialize(1);
  }
  next_stage[0]=out_block;
  if (valid_outputs<1){
     valid_outputs=1;
  };
  return 0;
}

int Snort_Block::internal_collector(){
  //this guy does not return...
  bool pending=true;
  //fd_set rfds;
  //struct timeval tv;
  int rvalue;
  UnifiedLogFileHeader file_header; 
  //unsigned char minibuf;
  char *fifoname="/tmp/snort-cam.log";
  //int counter=0;
  UnifiedLog log_header;
  char pkt_data[MAX_PACKET_PAYLOAD_LENGTH];
  struct pcap_pkthdr *pcap_hdr;
  dbi_result result;
  char query[SNORT_MAX_QUERY_LENGTH]; 
  char query_extra[256];
  Tagged_IP_Packet snort_packet;
  int offset=0;
  unsigned int flow_db_id;
  int data_link;
  Tagged_IPV4_Flow forward,reverse,side_effect;
  struct timespec delay;
  //bool found;
  int iterations;

  //ajust pointers...
  pcap_hdr=(struct pcap_pkthdr*)&log_header.pkth;
  snort_packet.pcap_hdr=(struct pcap_pkthdr*)&log_header.pkth;
  snort_packet.data=(u_char*)pkt_data;

  //do fifo open here!!
  read_fifo_fd=open(fifoname,O_RDONLY);
  if(read_fifo_fd<0){perror("cannot open ffifo for read\n"); exit(1);};
  fprintf(stderr,"open fifo done!-------------------\n");

  //now do header....
  rvalue=read(read_fifo_fd,&file_header,sizeof(UnifiedLogFileHeader));
  if (sizeof(UnifiedLogFileHeader)!=rvalue){
     perror("cannot read file header from snort.. aborting..\n");
     exit(1);
     } 
  fprintf(stderr, "magic file=%x\n",file_header.magic);
  if(LOG_MAGIC!=file_header.magic){
     perror("this does not look like a log file.....aborting\n");
     exit(1);
     }
  data_link=file_header.linktype;
  pending=false;
  
  //now iterate over the events
  do{
     //apparently select does not work ok for fifos....
     rvalue=read(read_fifo_fd,&log_header,sizeof(UnifiedLog));
     if (sizeof(UnifiedLog)!=rvalue){
        if(rvalue==0){
           sleep(1);
           if(input_done){
               // snort closed....
               fprintf(stderr,"snort block: snort terminated and input is done.. terminating thread\n");
               return 0;
               }
           else{
              //snort closed on error??
               fprintf(stderr,"snort block: snort terminated and input is not done.. terminating on error\n");
               exit(1);
               }
           }
        fprintf(stderr,"rvalue=%d\n",rvalue);
        perror("cannot packet file header from snort.. aborting..\n");
        exit(1);
     }
     //now read the packet data into a localtmp!!
     if((offset>=-1) && (offset<MAX_PACKET_PAYLOAD_LENGTH-2))
          memset(pkt_data,0x00,offset+2);  

     rvalue=read(read_fifo_fd,(u_char *)pkt_data,log_header.pkth.caplen);
     if (( int)log_header.pkth.caplen!=rvalue){
        perror("cannot read packet content from snort.. aborting..\n");
        exit(1);
     }
     //--now print
     #ifdef VERBOSE
     #ifdef VERBOSE_SNORT
     print_snort_event(&log_header.event);
     #endif
     #endif
     flow_db_id=0;
     offset=L2_Helpers::is_ipv4(pcap_hdr,(u_char *)pkt_data,data_link,0);
     snort_packet.ip_header_offset=offset;

     iterations=0;
     while((offset!=-1) && (0==flow_db_id) && (iterations<2) && (1==log_header.event.sig_generator)){
        query[0]=0;
        //found=false;
        //grab packet header info...
        rvalue=Flow_helpers::packet_to_ipv4_flows(&snort_packet,&forward,&reverse,&side_effect,true);       
 
        switch(rvalue){
              case 0:
                     if(forward.protocol==reverse.protocol){
                         query_extra[0]=0x00;
                         }
                     else{
                         snprintf(query_extra,255," OR (src_ip=%u AND dst_ip=%u AND ip_proto=%u AND "
                                                    "src_port=%u and dst_port=%u) ",
                                                     reverse.dest_ip,reverse.source_ip,reverse.protocol,
                                                     reverse.dst_port,reverse.src_port  );
                         }
                     snprintf(query,SBK_MAX_QUERY_SIZE-1,"SELECT flow_id,GREATEST(src_end_sec,dst_end_sec) as etime FROM flow "
                                         "WHERE sensor_id=%u AND src_start_sec<=%u AND "
                                             "(  (src_ip=%u AND dst_ip=%u AND ip_proto=%u AND "
                                                "src_port=%u AND dst_port=%u)"
                                             "OR (src_ip=%u AND dst_ip=%u AND ip_proto=%u AND "
                                                "src_port=%u and dst_port=%u) %s) "
                                         "HAVING etime>=%u "
                                         "ORDER BY src_start_sec limit 1",
                                          sensor_id,(unsigned int)log_header.pkth.ts.tv_sec,
                                          forward.source_ip,forward.dest_ip,forward.protocol,
                                          forward.src_port,forward.dst_port,
                                          reverse.source_ip,reverse.dest_ip,reverse.protocol,
                                          reverse.src_port,reverse.dst_port,
                                          query_extra
                                          ,(unsigned int)log_header.pkth.ts.tv_sec );


                      result=dbi_conn_query(conn,query);
                      if(!result){
                           fprintf(stderr,"%s\n",query);
                           perror("snort-block: problem on select flow case 0  "); exit(1);
                           }
                      if(dbi_result_next_row(result)) {
                             flow_db_id=dbi_result_get_long(result, "flow_id");
                             //found=true;
                      }
                      else{
                         delay.tv_sec=0;
                         delay.tv_nsec=100000000; //need some better heuristic!!!
                      }
                      rvalue=dbi_result_free(result);

                     //---and update local
                    break;
              case 1: //icmp related and do not match;
                      //try to find related...if not try direct
                      snprintf(query,SBK_MAX_QUERY_SIZE-1,"SELECT flow_id,GREATEST(src_end_sec,dst_end_sec) as etime FROM flow "
                                         "WHERE sensor_id=%u AND ip_proto=%u AND src_start_sec<=%u AND "
                                             "(  src_ip=%u AND dst_ip=%u AND "
                                                "src_port=%u AND dst_port=%u) "
                                         "HAVING etime>=%u "
                                         "ORDER BY src_start_sec limit 1",
                                          sensor_id,side_effect.protocol,(unsigned int)log_header.pkth.ts.tv_sec,
                                          side_effect.source_ip,side_effect.dest_ip,side_effect.src_port,side_effect.dst_port,
                                          (unsigned int)log_header.pkth.ts.tv_sec );


                      result=dbi_conn_query(conn,query);
                      if(!result){
                           fprintf(stderr,"%s\n",query);
                           perror("snort_collect: problem on select, flow case 1 "); exit(1);
                           }
                      if(dbi_result_next_row(result)) {
                             flow_db_id=dbi_result_get_long(result, "flow_id");
                             //found=true;
                          }
                      else{
                         delay.tv_sec=0;
                         //delay.tv_nsec=20000000;
                         delay.tv_nsec=100000000;
                         }
                      rvalue=dbi_result_free(result);

                     break;
              default:delay.tv_nsec=0;
                      delay.tv_sec=0;
                      //found=true;
                     break;
            }//end switch
        //if not found, sleep!
        if(0==flow_db_id ){
            fprintf(stderr, "flow_id=%u\n",flow_db_id);
            fprintf(stderr,"NOT FOUND: Query='%s'\n",query);
            do{
               rvalue=nanosleep(&delay,NULL);
            }while(0!=rvalue && EINTR==errno);
            if(0!=rvalue) {
                perror("Snort_collector: error on nanosleep\n");
                exit(1);
                };
            }
        
        iterations++;
        }//closes the while
    
    //insert in db...
    //snpritnf.....
    snprintf(query,SBK_MAX_QUERY_SIZE-1," INSERT DELAYED INTO ids  "
                                         "(sensor_id,sig_id,flow_id,"
                                         " sec,usec,priority,sig_rev,"
                                         " sig_gen,classification) "
                                         "VALUES (%u,%u,%u, %u,%u,%u,%u,  %u,%u) ",
                                          sensor_id,log_header.event.sig_id,flow_db_id,
                                          (unsigned int)log_header.event.ref_time.tv_sec,
                                              (unsigned int)log_header.event.ref_time.tv_usec,
                                              log_header.event.priority,log_header.event.sig_rev,
                                          log_header.event.sig_generator,log_header.event.classification );


    result=dbi_conn_query(conn,query);
    if(!result){
        fprintf(stderr,"%s\n",query);
        perror("problem on insert ids case 0 "); exit(1);
        }
    rvalue=dbi_result_free(result);
    
     
  }while((input_done==false) && (pending==false));

  close(read_fifo_fd);

  fprintf(stderr,"Snort block:internal collector done\n");
  pthread_exit(NULL);
  return 0;
}


#endif
