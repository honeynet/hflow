// (C) 2007 The Trustees of Indiana University.  All rights reserved.
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



#ifndef PZEROF_BLOCK_HPP
#define PZEROF_BLOCK_HPP

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
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <dbi/dbi.h>
#include "pcap_outfile_block.hpp"
#include "l2_helpers.hpp"
#include "active_ipv4_flow_db.hpp"

using namespace std;
//local defines
#define PZEROF_MAX_QUERY_LENGTH 1024


class p0f_Block: public Processing_Block{
  private:
    int packet_pipe_fd[2];
    int os_ident_pipe_fd[2];
    pid_t child_pid;
    pthread_t collector_thread;
    Pcap_Outfile_Block pcap_block; //code reuse   
    volatile bool input_done; 
    dbi_conn conn;
    unsigned int sensor_id;
    //volatile unsigned int last_timestamp_seen;

  public:
    inline int entry_point(const Tagged_Element *in_packet){return entry_point((Tagged_IP_Packet *) in_packet);};
    int entry_point(const Tagged_IP_Packet *in_packet);
    int set_output_point(Processing_Block *out_block);
    int set_output_point(Processing_Block *,int out_index);
    int initialize(int numoutputs);
    int initialize(int in_numoutputs,  char* dbtype, char* dbname, char* username,char *password);
    int initialize(int in_numoutputs,  char* dbtype, char* dbname, char* username,char *password,unsigned int in_sensor_id);
    int internal_collector();//this guy never returns
    int decode_p0f_output_line(char *line, char **genre, char **detail, char **src_ip, char **src_port, char **dst_ip,char **dst_port,char **timestamp);
    p0f_Block();
    ~p0f_Block();
};

void *p0f_block_thread_func(void *inblock){
              p0f_Block *in_class;
              in_class=(p0f_Block *)inblock;
              in_class->internal_collector();
             return NULL;
}

////////Class implementation
p0f_Block::p0f_Block(){
   initialized=false;
   input_done=false;
   next_stage=NULL;
   num_outputs=0;
   sensor_id=0;
};

p0f_Block::~p0f_Block(){
  int rvalue;
  int status;
  fprintf(stderr,"p0f block start destructor\n");
  if (true==initialized){
     close(packet_pipe_fd[1]);
     sleep(1);
     input_done=true;
     //signal child
     fprintf(stderr,"p0f block (%d): about to send kill to %d\n",getpid(),child_pid);
     rvalue=kill(child_pid,SIGTERM);
     //sleep(1);
     //wait
     fprintf(stderr, "sigkill sent\n");
     rvalue=waitpid(child_pid,&status,0);
     fprintf(stderr, "waitpid returned\n");
     //forget about joining for now..
     rvalue=pthread_join(collector_thread,NULL);
     if(0!=rvalue){perror("p0f_block:error on pthread_join:");};
     }
  fprintf(stderr,"p0f block destroyed\n");
}


int p0f_Block::initialize(int in_numoutputs){
   return initialize(in_numoutputs,"mysql","hflow","hflowdaemon","");
}


int p0f_Block::initialize(int in_numoutputs,  char* dbtype, char* dbname, char* username,char *password){
   return initialize(in_numoutputs, dbtype, dbname,username,password,0);

}
int p0f_Block::initialize(int in_numoutputs,  char* dbtype, char* dbname, char* username,char *password,unsigned int in_sensor_id)
{
  int i;
  int rvalue;
  //mode_t default_mode=(S_IRUSR | S_IWUSR | S_IRGRP|S_IROTH );
  //char *fifoname="/tmp/snort-cam.log"; 
   
  fprintf(stderr,"start of p0f block_init\n");
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
  /*
  rvalue=mkfifo(fifoname,default_mode);
  if(0!=rvalue){
     if (EEXIST==errno){
        fprintf(stderr,"p0f_block:fifo exists attempting to delete\n");
        //delete and recreate
        rvalue=unlink(fifoname);
        if(0!=rvalue){
            perror("p0f block: delete of old fifo failed:");exit(1);
            }
        fprintf(stderr,"p0f_block: successful deletion\n");
        rvalue=mkfifo(fifoname,default_mode);
        if (0!=rvalue){
             perror("p0f block: replace: Cannot make fifo:");exit(1);
             }
        }
     else{
        perror("p0f block: Cannot make fifo:");exit(1);
        }
  }
  */
  //create in_packet pipe
  rvalue=pipe(packet_pipe_fd);
  if(0!=rvalue){perror("p0f block: Cannot make packet pipe:");exit(1);} 
  fprintf(stderr,"p0f_block: success creating packet pipe\n");

  rvalue=pipe(os_ident_pipe_fd);
  if(0!=rvalue){perror("p0f block: Cannot make packet pipe:");exit(1);}
  fprintf(stderr,"p0f_block: success creating packet pipe\n");


 
  /*
  //create the snort outdatafile
  snort_out_fd=open("p0f_out.txt", O_WRONLY|O_CREAT |O_TRUNC,default_mode);
  if(0!=rvalue){perror("p0f block: Cannot open p0f outfile:");exit(1);}
  */

  //read_fifo_fd=0;

  //create new thread
  // rvalue=pthread_create(&collector_thread,NULL,snort_block_thread_func,(void*)this);
  // if(0!=rvalue){perror("cannot create new thread in dbinserter"); exit(1);};

  //fork
  child_pid=fork();
  if(-1==child_pid){perror("p0f block:Fork Failiure:");exit(1);}  
  //on fork do stuff
  if(0==child_pid){//this is the child
     //reduce prio
     //rvalue=nice(1);
     //if(0!=rvalue){perror("Snort block: child: Error on nice:");exit(1);}
     //do fd magic
     rvalue=close(0);
     if(0!=rvalue){perror("p0f block: child: Error closing stdin:");exit(1);}
     rvalue=dup(packet_pipe_fd[0]);
     if(0!=rvalue){perror("p0f block: child: Dup failed:");exit(1);}

     rvalue=close(1);
     if(0!=rvalue){perror("p0f block: child: Error closing stdout:");exit(1);}
     rvalue=dup(os_ident_pipe_fd[1]);
     if(1!=rvalue){perror("p0f block: child: stdout Dup failed:");exit(1);}
     rvalue=close(2);
     if(0!=rvalue){perror("p0f block: child: Error closing stderr:");exit(1);}
     rvalue=dup(os_ident_pipe_fd[1]);
     if(2!=rvalue){perror("p0f block: child: stderr Dup failed:");exit(1);}
     


     rvalue=close(packet_pipe_fd[1]);
     if(0!=rvalue){perror("p0f block: child: Error closig pipe wr:");exit(1);}
     rvalue=close(os_ident_pipe_fd[0]);
     if(0!=rvalue){perror("p0f block: child: Error closig pipe wr:");exit(1);}


     //rvalue=dup2(pipe_fd[0],0);
     //rvalue=dup(pipe_fd[0]);
     //if(0!=rvalue){perror("Snort block: child: Dup failed:");exit(1);}
     //rvalue=execlp("snort","snort","-r","-","-c","snort.conf","-l", "/tmp/snortest",NULL);
     //rvalue=execlp("/usr/sbin/tcpdump" ,"/usr/sbin/tcpdump" ,"-r", "-","-w","/tmp/snort-cam.log",NULL);
     rvalue=execlp("/usr/sbin/p0f","/usr/sbin/p0f","-s","-","-q","-l","-ttt", (char *) NULL);
     if(0!=rvalue){perror("p0f block: child: Failed p0f exec:");exit(1);}
     //should not reach next line
     fprintf(stderr, "Snort aborted!!! , terminating ");
     exit(1);
     }
  else{//this is the parent
     rvalue=close(packet_pipe_fd[0]);
     if(0!=rvalue){perror("p0f block: parent: Error closig pipe wr:");exit(1);}
     rvalue=close(os_ident_pipe_fd[1]);
     if(0!=rvalue){perror("p0f block: parent: Error closing pipe");exit(1);}
    //exit(1);
     //rvalue=sleep(1);
     //write a tpdump header to the fifo
     }

  fprintf(stderr,"fork section done!\n");
  //open fd for readfifo
  //read_fifo_fd=open(fifoname,O_RDONLY);
  //if(read_fifo_fd<0){perror("cannot open ffifo for read\n"); exit(1);};
  //fprintf(stderr,"open fifo done!\n");

  //create new thread
  rvalue=pthread_create(&collector_thread,NULL,p0f_block_thread_func,(void*)this);
  if(0!=rvalue){perror("cannot create new thread in dbinserter"); exit(1);};



  ///initialize the pcap dumper
  pcap_block.initialize_on_open_fd(packet_pipe_fd[1]); 
  
  fprintf(stderr,"snort init section done!\n");
 
  initialized=true;
  valid_outputs=0;
  return 0; 
};

int p0f_Block:: decode_p0f_output_line(char *line, char **genre, char **detail, char **src_ip, char **src_port, char **dst_ip,char **dst_port,char **timestamp){
   //most un-elegant function
   //int rvalue;
   char *strtok_state;
   char *trash;
   //char *current=line;
   int i; 

   *timestamp=strtok_r(line,">",&strtok_state);
   if (NULL==(*timestamp)){
       return -1;
   }
   (*timestamp)++;
   

   *src_ip=strtok_r(NULL,":",&strtok_state);
   if (NULL==(*src_ip)){
       return -2;
   }
   (*src_ip)++;

   *src_port=strtok_r(NULL," \t",&strtok_state);
   if (NULL==(*src_port)){
       return -3;
   }
   //now skip the minus
   trash=strtok_r(NULL," \t",&strtok_state);
   if (NULL==(trash)){
       return -4;
   }
   *genre=strtok_r(NULL," \t",&strtok_state);
   if (NULL==(*genre)){
       return -5;
   }
   *detail=strtok_r(NULL,"(-",&strtok_state);
   if (NULL==(*detail)){
       return -6;
   }
   //now find the '>'
   if(*strtok_state!='>'){
     trash=strtok_r(NULL,">",&strtok_state);
     if (NULL==(trash)){
       return -7;
     }
   }
   *dst_ip=strtok_r(NULL,":",&strtok_state);
   if (NULL==(*dst_ip)){
       return -8;
   }
   for(i=0;i<3 && 0==isdigit(**dst_ip) ;i++){
     (*dst_ip)++;
   }
   *dst_port=strtok_r(NULL," \n(",&strtok_state);
   if (NULL==(*dst_port)){
       return -9;
   }

   return 0;
}

int p0f_Block::entry_point(const Tagged_IP_Packet *in_packet){
  //assumes it is initialized
  int i;
  //int rvalue;
  Tagged_Packet *pack_vect;
  Tagged_IPV4_Flow *current_flow;

  //cout << "inpacket snort_block" <<endl;
  ///processs here
  
   //write to pipe_fd[1]...
  pack_vect=(Tagged_Packet *)in_packet;

  //only do tagged packets, as are the only ones we can associate to
  // this is suboptimal, but is a very good and fast heuristic
  // and we do not want to decode the packet again!
  if(in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr!=NULL){
       current_flow=(Tagged_IPV4_Flow *)(in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr); //ugly
        //we are doing something awful, reading from a possibly invalid memory location or
        // a no longer valid memory location, this could work for real time, but problems could
        // arise when reading from files..
        // two options exist... slow down the reader OR use locking I wish I could do without locking
        // the other big assumtion here is the fact that the system reads a whole 32bit word at a time....

      assert(in_packet->pcap_hdr!=NULL);      
      if(current_flow->stats.src.packets<3){
           //last_timestamp_seen=(unsigned int)current_flow->stats.end_time();
           //we only need the initial packets, nothing else is really needed          
           pcap_block.entry_point(in_packet);
      }
  }

  //pcap_block.entry_point(in_packet);
  //rvalue=fsync(pipe_fd[1]);
  //cout << "flushed snort_block" <<endl;

   // call each valid output
  for(i=0;i<valid_outputs;i++){
     (next_stage[i])->entry_point(in_packet);
  }
  return 0;
}

int p0f_Block::set_output_point(Processing_Block *out_block){
   
  if (false==initialized){
     initialize(1);
  }
  next_stage[0]=out_block;
  if (valid_outputs<1){
     valid_outputs=1;
  };
  return 0;
}

int p0f_Block::internal_collector(){
  //this guy does not return...
  bool pending=true;
  //fd_set rfds;
  //struct timeval tv;
  int rvalue;
  //UnifiedLogFileHeader file_header; 
  //unsigned char minibuf;
  //char *fifoname="/tmp/snort-cam.log";
  //int counter=0;
  //UnifiedLog log_header;
  //char pkt_data[MAX_PACKET_PAYLOAD_LENGTH];
  //struct pcap_pkthdr *pcap_hdr;
  dbi_result result;
  char query[PZEROF_MAX_QUERY_LENGTH];
  char p0f_line[256]; 
  char query2[PZEROF_MAX_QUERY_LENGTH];
  //Tagged_IP_Packet p0f_packet;
  //int offset=0;
  unsigned int flow_db_id;
  //int data_link;
  //Tagged_IPV4_Flow forward,reverse,side_effect;
  struct timespec delay;
  //bool found;
  int iterations;
  FILE *file_stream;
  char *genre, *detail, *src_ip,*dst_ip, *src_port, *dst_port,*timestamp;
  int decoded;
  unsigned int os_db_id=0;

  //ajust pointers...
  //pcap_hdr=(struct pcap_pkthdr*)&log_header.pkth;
  //p0f_packet.pcap_hdr=(struct pcap_pkthdr*)&log_header.pkth;
  //p0f_packet.data=(u_char*)pkt_data;

  file_stream=fdopen(os_ident_pipe_fd[0],"r");
  if (NULL==file_stream){
     perror("cannot associate file stream to fifo.. aborting\n");
     exit(1);
     }

  //do fifo open here!!
  //read_fifo_fd=open(fifoname,O_RDONLY);
  //if(read_fifo_fd<0){perror("cannot open ffifo for read\n"); exit(1);};
  //fprintf(stderr,"open fifo done!-------------------\n");


  //now do header.... not needed remove later!!!
  /*rvalue=read(read_fifo_fd,&file_header,sizeof(UnifiedLogFileHeader));
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
  */
  pending=false;
  //now iterate over the events
  do{
     if(NULL==fgets(p0f_line,255,file_stream)){
        sleep(1);
        if(input_done){
            //p0f closed
            fprintf(stderr,"p0f block: p0f terminated and input is done.. terminating thread\n");
            return 0;

            }
        else{
            fprintf(stderr,"p0f block: p0f terminated and input is not done.. terminating on error\n");
            exit(1);
            }
        }
     //fprintf(stderr,"%s\n",p0f_line);
     rvalue=decode_p0f_output_line(p0f_line, &genre, &detail, &src_ip, &src_port, &dst_ip,&dst_port,&timestamp);
     if(rvalue<0){
        //fprintf(stderr,"error decoding '%s'\n",p0f_line);
        fprintf(stderr, " P0f Decoding error: rvalue=%d genre='%s' , detail='%s' timestamp=%s %s:%s -> %s:%s\n",rvalue,genre,detail,timestamp,src_ip,src_port,dst_ip,dst_port);

        } 
     #ifdef VERBOSE  
     else{
        fprintf(stderr, "P0f: genre='%s' , detail='%s' timestamp=%s %s:%s -> %s:%s\n",genre,detail,timestamp,src_ip,src_port,dst_ip,dst_port);
         
        }
     #endif
     decoded=rvalue;
    /*
     //apparently select does not work ok for fifos....
     rvalue=read(os_ident_pipe[0],&log_header,sizeof(UnifiedLog));
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
     print_snort_event(&log_header.event);
     offset=L2_Helpers::is_ipv4(pcap_hdr,(u_char *)pkt_data,data_link,0);
     snort_packet.ip_header_offset=offset;
*/
     flow_db_id=0;
     iterations=0;
     //while commented for now, will go back in
     while((decoded>=0) && (0==flow_db_id) && (iterations<2) ){
        query[0]=0;
        //found=false;
        //grab packet header info...
        //rvalue=Flow_helpers::packet_to_ipv4_flows(&snort_packet,&forward,&reverse,&side_effect,true);       
       //next lines replace the switch
        snprintf(query,SBK_MAX_QUERY_SIZE-1, "SELECT flow_id ,GREATEST(src_end_sec,dst_end_sec) as etime from flow "
                                            "WHERE sensor_id=%u AND ip_proto=6 AND "
                                            "src_ip=inet_aton('%s') AND src_port=%s AND "
                                            "dst_ip=inet_aton('%s') AND dst_port=%s AND "
                                            "src_start_sec>=%s-20 "
                                            "HAVING etime>=%s-1 "
                                            "ORDER BY src_start_sec LIMIT 1",
                                            sensor_id, 
                                            src_ip,src_port,dst_ip,dst_port,
                                            timestamp,timestamp );
       
        result=dbi_conn_query(conn,query);
        if(!result){
            fprintf(stderr,"%s\n",query);
            perror("p0f-block: problem on query 0  "); exit(1);
            }
        if(dbi_result_next_row(result)) {
            flow_db_id=dbi_result_get_long(result, "flow_id");
            //found=true;
            }
        else{
            delay.tv_sec=0;
            delay.tv_nsec=20000000; //need some better heuristic!!!
            }
         rvalue=dbi_result_free(result);
 

        //if not found, sleep!
        if(0==flow_db_id ){
            //fprintf(stderr, "flow_id=%u\n",flow_db_id);
            #ifdef VERBOSE
            fprintf(stderr,"P0f NOT FOUND: Query='%s'\n",query);
            fprintf(stderr,"P0f NOT FOUND iters=%u\n",iterations );
            #endif
            do{
               rvalue=nanosleep(&delay,NULL);
            }while(rvalue!=0 && EINTR==errno);
            if(0!=rvalue) {
                perror("p0f_collector: error on nanosleep\n");
                exit(1);
                };
            }
        
        iterations++;
        }//closes the while
    // now we have to find the genre and details in our sensor id, and if not found, insert one and select
    if (decoded>=0){
        os_db_id=0;
        snprintf(query,PZEROF_MAX_QUERY_LENGTH-1, "SELECT os_id FROM os WHERE "
                                              "sensor_id=%u AND genre='%s' AND detail='%s' LIMIT 1",
                                              sensor_id,genre,detail);
        
        result=dbi_conn_query(conn,query);
        if(!result){
             fprintf(stderr,"%s\n",query);
             perror("p0f-block: problem on query select os  "); exit(1);
             }
        if(dbi_result_next_row(result)) {
             os_db_id=dbi_result_get_long(result, "os_id");
             //found=true;
             }
         rvalue=dbi_result_free(result);
         if(0==os_db_id){
             //not found, need to insert
             snprintf(query2,PZEROF_MAX_QUERY_LENGTH-1,"INSERT INTO os "
                                                       "(sensor_id,genre,detail) "
                                                       "VALUES (%u,'%s','%s') ",
                                                       sensor_id,genre,detail);

             result=dbi_conn_query(conn,query2);
             if(!result){
                 fprintf(stderr,"%s\n",query2);
                 perror("p0f-block: problem on query select os  "); exit(1);
             }
             rvalue=dbi_result_free(result);
             //now we query again!
             result=dbi_conn_query(conn,query);
             if(!result){
                  fprintf(stderr,"%s\n",query);
                  perror("p0f-block: problem on query select os  "); exit(1);
                  }
             if(dbi_result_next_row(result)) {
                 os_db_id=dbi_result_get_long(result, "os_id");
                 //found=true;
                  }
             rvalue=dbi_result_free(result);

             }

         }
    if((os_db_id!=0) && (flow_db_id!=0)){
        //do insertion of os into flow
        snprintf(query,PZEROF_MAX_QUERY_LENGTH-1, "UPDATE flow SET client_os_id=%u  WHERE "
                                              "sensor_id=%u AND flow_id=%u",
                                              os_db_id,sensor_id,flow_db_id);

        result=dbi_conn_query(conn,query);
        if(!result){
             fprintf(stderr,"%s\n",query);
             perror("p0f-block: problem on query update os on flow  "); exit(1);
             }
         rvalue=dbi_result_free(result);

        
        }  
 
    
    //insert in db...
    //snpritnf.....
    /*THIS GOES IN!!!
    snprintf(query,SBK_MAX_QUERY_SIZE-1," INSERT INTO ids  "
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
    */
     
  }while((input_done==false) && (pending==false));

  close(os_ident_pipe_fd[0]);

  fprintf(stderr,"p0f:internal collector done\n");
  pthread_exit(NULL);
  return 0;
}


#endif
