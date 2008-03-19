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



#ifndef FLOW_BD_INSERTER_BLOCK_HPP
#define FLOW_DB_INSERTER_BLOCK_HPP

/*
Flow inserter into DB.. first threaded block we make...why?
   we do not know a priori how long a db operation can take
   so we need to separate the processing of data

   this hpp requires: -lpthread, -ldl ,-ldbi  !!

*/
#include "element.h"
#include <pcap.h>
#include "active_ipv4_flow_db.hpp"
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

///////////////////////////////
//why this? to have a database independent interface
//    already mysql forces clients that use their lib  to be GPL, i do not like this
//    so, if in the future someone wants to make a LGPL client lib we can use it
//    with minor changes to the apps...
//    and yes this is slower than to talk directly in terms of binary data..
#include <dbi/dbi.h>

//#include <map>
#include <list>


using namespace std;

////// Class definition
class Flow_DB_Inserter_Block: public Processing_Block{
  private:
    int last_warn_size;
    pthread_mutex_t in_queue_mutex;
    list<Tagged_IPV4_Flow> in_queue;
    sem_t queue_sem;
    pthread_t inserter_thread;
    dbi_conn conn;
    volatile int queue_size;
    bool db_id_added_to_flow;
    unsigned int sensor_id;
    //int initialized;
public:
  public:
/*    static void *db_inserter_thread_func(void *inblock)
            {Flow_DB_Inserter_Block *in_class;
              in_class=(Flow_DB_Inserter_Block *)inblock;
              in_class->internal_collector();
             }
*/
    inline int entry_point(const Tagged_Element *in_flow){return entry_point((Tagged_IPV4_Flow *) in_flow);};
    int entry_point( Tagged_IPV4_Flow *in_flow);
    int set_output_point(Processing_Block *out_block);
    int initialize(int in_numoutputs,char* dbtype, char* dbname, char* username,char *password);
    int initialize(int in_numoutputs,char* dbtype, char* dbname, char* username,char *password,unsigned int in_sensor_id);

    int DB_updater(Tagged_IP_Packet *in_packet);
    Flow_DB_Inserter_Block();
    ~Flow_DB_Inserter_Block();
  //private:
    int internal_collector(); //should never come back!
    int db_flow_insert(Tagged_IPV4_Flow *in_flow);
    int db_flow_insert_mysql(Tagged_IPV4_Flow *in_flow);
    unsigned int set_sensor_id(const unsigned int in_id){sensor_id=in_id; return sensor_id;};
};

void *db_inserter_thread_func(void *inblock)
            {Flow_DB_Inserter_Block *in_class;
              in_class=(Flow_DB_Inserter_Block *)inblock;
              in_class->internal_collector();
             return NULL;
             }


/////////////////////////////////////
////////Class implementation

Flow_DB_Inserter_Block:: Flow_DB_Inserter_Block(){
  initialized=false;
  sensor_id=0;
  queue_size=0;
 };
//
 Flow_DB_Inserter_Block::~ Flow_DB_Inserter_Block(){
 int i;
 int semval,rvalue;
 if (initialized){
     //wait till queue is flushed or for 5 secs
     for (i=0;i<5;i++){
        rvalue=sem_getvalue(&queue_sem,&semval);
        if(0!=rvalue){
            cout<< "error on destructor for DB_INSERTER"<<endl;
            i=10;
        }
        else{
            if(0==semval){ i=6;}
            else{
              sleep(1);
            }
        }
     }
     if (5==i){
        cout<<"queue not empty after 5 secs"<<endl;
     }
     dbi_conn_close(conn);
 }
 //cout<<"flow db destroyed!"<<endl;
};

////
 int Flow_DB_Inserter_Block::entry_point( Tagged_IPV4_Flow *in_flow){
      // steps:
      //  1. copy data into queue
      //         a. lock
      //         b. push
      //         c. unlock;
      //  2. increment the semaphore
    int rvalue;
    int local_queue_size;
    struct timespec delay;    

    rvalue=pthread_mutex_lock(&in_queue_mutex);
    if(0!=rvalue){perror("error on mutex lock, entry"); exit(1);};
    in_queue.push_back(*in_flow);
    queue_size++;
    local_queue_size=queue_size;
    rvalue=pthread_mutex_unlock(&in_queue_mutex);
    if(0!=rvalue){perror("error on mutex unlock, entry"); exit(1);};
    rvalue=sem_post(&queue_sem);
    if(0!=rvalue){perror("error on queue post, entry"); exit(1);};

    if((false==live_read) && (local_queue_size>6) ){
       delay.tv_sec=0;
       delay.tv_nsec=2000000;
       if(local_queue_size>15){
          delay.tv_nsec=10000000;
          
          if(local_queue_size>40){
             delay.tv_nsec=100000000;
             }
             if (local_queue_size>1000){
                  delay.tv_sec=1;
             }
          }
       nanosleep(&delay,NULL);
       }     


    return 0;
 };
////////////
int Flow_DB_Inserter_Block::set_output_point(Processing_Block *out_block){

  if (false==initialized){
     return -1;
  }
  next_stage[0]=out_block;
  if (valid_outputs<1){
     valid_outputs=1;
  };
  return 0;
};


int Flow_DB_Inserter_Block::initialize(int in_numoutputs,char* dbtype, char* dbname, char* username,char *password){
   return initialize(in_numoutputs,dbtype,dbname, username,password,0);
}

int Flow_DB_Inserter_Block::initialize(int in_numoutputs,char* dbtype, char* dbname, char* username,char *password,unsigned int in_sensor_id)
{
   //initializer failures are fatal, should result in an exit!!
   //   need to initialize: 
   //                  locking vars
   //                  db
   //                  thread

   int rvalue;

   sensor_id=in_sensor_id;

   rvalue=sem_init(&queue_sem,0, 0);
   if(0!=rvalue){perror("cannot initialize semaphore in dbinserter"); exit(1);};
   rvalue=pthread_mutex_init(&in_queue_mutex,0);
   if(0!=rvalue){perror("cannot initialize mutex in dbinserter"); exit(1);};

   //initialize DB //need to add error check
   if (false==dbi_initialized){
  //    dbi_initialize(NULL);
        if (0>dbi_initialize(NULL)){
           perror("Flow DB inserter block: error initializing dbi interface.. aborting\n");
           exit(1);
           }
        fprintf(stderr,"flow db initialized dbi\n");
        dbi_initialized=true;
        }


   conn=dbi_conn_new(dbtype);
   dbi_conn_set_option(conn,"host","localhost");
   dbi_conn_set_option(conn, "dbname", dbname);
   dbi_conn_set_option(conn, "username", username);
   dbi_conn_set_option(conn, "password", password);
  
   rvalue=dbi_conn_connect(conn);
   if(0>rvalue){
    perror("failed to connect to database .. exiting\n");
    exit(1);
    }
   //fprintf(stderr,"dbi_conn_connect rvalue=%d",rvalue);
   


   //create new thread
   rvalue=pthread_create(&inserter_thread,NULL,db_inserter_thread_func,(void*)this);
   if(0!=rvalue){perror("cannot create new thread in dbinserter"); exit(1);};

   initialized=1;
   return 0;
};

///////
int Flow_DB_Inserter_Block::internal_collector(){
   //this is the main inserter thread
   int rvalue;
   int list_size;
   Tagged_IPV4_Flow *current_flow;
   list<Tagged_IPV4_Flow>::iterator flow_it;
   while (1){
        // simple loop:
        //   1. sem wait
        //   2. get handle of  localbuff (critical section).
        //          a. mutex lock
        //          b. grab ptr
        //          c. mutex unlock
        //   ///3. sem post// actually no post, post are handled by the inserter
        //   3. do db insert
        //   4. send flow to output
        //   5. delete data // second critical section (pop);

        //step1
        try_again_sem_wait:
        rvalue=sem_wait(&queue_sem);
        //if(0!=rvalue){perror("error on sem_wat"); exit(1);};
        if(0!=rvalue){
            if (errno== EINTR ){
                 goto try_again_sem_wait;
               }
            perror("Flow DB Inserter: error on sem_wat");
            exit(1);
        }

        //step2 get handle
        rvalue=pthread_mutex_lock(&in_queue_mutex);
        if(0!=rvalue){perror("error on mutex lock, collector"); exit(1);};
        current_flow=&(*in_queue.begin());  
        rvalue=pthread_mutex_unlock(&in_queue_mutex);
        if(0!=rvalue){perror("error on mutex unlock, collector"); exit(1);};
        
        //setep 3 do db_insert
#define USE_MYSQL_SQL
#ifdef USE_MYSQL_SQL
        db_flow_insert_mysql(current_flow);        
#else
        db_flow_insert(current_flow);
#endif
        ///step 5 delete
        rvalue=pthread_mutex_lock(&in_queue_mutex);
        if(0!=rvalue){perror("error on mutex lock, collector"); exit(1);};     
        in_queue.pop_front();
        list_size=in_queue.size();
        queue_size--;
        rvalue=pthread_mutex_unlock(&in_queue_mutex);
        if(0!=rvalue){perror("error on mutex unlock, collector"); exit(1);};
        
        if (list_size>10){
           if(list_size>=last_warn_size){
              cout <<"warning: large list size, size=" <<list_size<<endl;
              last_warn_size=list_size;
           }
             
        }
        else{last_warn_size=0;}


   }
   return 0;
}

///////
int Flow_DB_Inserter_Block::db_flow_insert(Tagged_IPV4_Flow *in_flow){//should be renamed mysql insert!!
   static char *section1="INSERT INTO flow"
                "(sensor_id, "
                " src_ip,dst_ip,src_port,dst_port,ip_proto,"
                " src_start_sec,src_start_msec,src_end_sec,src_end_msec,"
                " src_packets,src_bytes,src_ip_flags,src_tcp_flags,src_icmp_packets,src_icmp_seen,"
                " dst_start_sec,dst_start_msec,dst_end_sec,dst_end_msec,"
                " dst_packets,dst_bytes,dst_ip_flags,dst_tcp_flags,dst_icmp_packets,dst_icmp_seen, "
                " marker_flags) "
                " VALUES ";
   //static char *section2=" ON DUPLICATE KEY UPDATE SET ";
   int rvalue=-1;
   //static char *flow_id_query;
   char query[10000];
   char query2[2000]; 
   //char added[10000];
   dbi_result result;
   unsigned int flow_db_id; 
   unsigned int last_time;
   unsigned int curr_packet_size;
  
   db_id_added_to_flow=false;

   if (0==in_flow->annot[FLOW_ANNOT_DB_ID].as_int32){ //no db id known, do an insert
/*
        snprintf(query, 10000,
                 "%s (%u,  %u,%u,%u,%u,%u,    %u,%u,%u,%u, %u,%u,%u,%u,%u,%u,%u,  %u,%u,%u,%u, %u,%u,%u,%u,%u,%u  )"
                 " ON DUPLICATE KEY UPDATE src_end_sec=%u,src_end_msec=%u,"
                 "src_packets=%u,src_bytes=%u,src_ip_flags=%u,src_tcp_flags=%u,src_icmp_packets=%u,src_icmp_seen=%u,"
                 "dst_start_sec=%u,dst_start_msec=%u,dst_end_sec=%u,dst_end_msec=%u,"
                 "dst_packets=%u,dst_bytes=%u,dst_ip_flags=%u,dst_tcp_flags=%u,dst_icmp_packets=%u,dst_icmp_seen=%u,"
                 "marker_flags=%u",
                  section1,
                  sensor_id,
                  in_flow->source_ip,in_flow->dest_ip,in_flow->src_port,in_flow->dst_port, in_flow->protocol,
                  in_flow->stats.src.start_time,in_flow->stats.src.start_msec,
                  in_flow->stats.src.end_time,in_flow->stats.src.end_msec,
                  in_flow->stats.src.packets,in_flow->stats.src.bytes,in_flow->stats.src.ip_flags,
                  in_flow->stats.src.tcp_flags,in_flow->stats.src.icmp_packets,in_flow->stats.src.icmp_seen,
                  in_flow->stats.dst.start_time,in_flow->stats.dst.start_msec,
                  in_flow->stats.dst.end_time,in_flow->stats.dst.end_msec,
                  in_flow->stats.dst.packets,in_flow->stats.dst.bytes,in_flow->stats.dst.ip_flags,
                  in_flow->stats.dst.tcp_flags,in_flow->stats.dst.icmp_packets,in_flow->stats.dst.icmp_seen,
                  (unsigned int) in_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32,

                  in_flow->stats.src.end_time,in_flow->stats.src.end_msec,
                  in_flow->stats.src.packets,in_flow->stats.src.bytes,in_flow->stats.src.ip_flags,
                  in_flow->stats.src.tcp_flags,in_flow->stats.src.icmp_packets,in_flow->stats.src.icmp_seen,
                  in_flow->stats.dst.start_time,in_flow->stats.dst.start_msec,
                  in_flow->stats.dst.end_time,in_flow->stats.dst.end_msec,
                  in_flow->stats.dst.packets,in_flow->stats.dst.bytes,in_flow->stats.dst.ip_flags,
                  in_flow->stats.dst.tcp_flags,in_flow->stats.dst.icmp_packets,in_flow->stats.dst.icmp_seen,
                  (unsigned int) in_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32
                   );
        result=dbi_conn_query(conn,query);
        
        rvalue=dbi_result_free(result);  
        //cout<<"inserting: "<< query<<endl;

*/
        snprintf(query,10000, "SELECT flow_id ,GREATEST(src_end_sec,dst_end_sec) as etime from flow "
                                            "WHERE sensor_id=%u AND ip_proto=%d AND "
                                            "src_ip=%u AND src_port=%u AND "
                                            "dst_ip=%u AND dst_port=%u AND "
                                            "src_start_sec=%u "
                                            "ORDER BY src_start_sec LIMIT 1",
                                            sensor_id, in_flow->protocol,
                                            in_flow->source_ip,in_flow->src_port,
                                            in_flow->dest_ip,in_flow->dst_port,
                                            in_flow->stats.src.start_time );

        result=dbi_conn_query(conn,query);
        if(!result){
            fprintf(stderr,"%s\n",query);
            perror("dbins-block: problem on query 0  "); exit(1);
            }
        if(dbi_result_next_row(result)) {
            //found==true!!
            flow_db_id=dbi_result_get_long(result, "flow_id");
            rvalue=dbi_result_free(result);
            //do update
            snprintf(query, 10000,
                 "UPDATE flow "
                 " SET  src_end_sec=%u,src_end_msec=%u,"
                 "src_packets=%u,src_bytes=%u,src_ip_flags=%u,src_tcp_flags=%u,src_icmp_packets=%u,src_icmp_seen=%u,"
                 "dst_start_sec=%u,dst_start_msec=%u,dst_end_sec=%u,dst_end_msec=%u,"
                 "dst_packets=%u,dst_bytes=%u,dst_ip_flags=%u,dst_tcp_flags=%u,dst_icmp_packets=%u,dst_icmp_seen=%u,"
                 "marker_flags=%u "
                 " WHERE sensor_id=%u and flow_id=%u",

                  in_flow->stats.src.end_time,in_flow->stats.src.end_msec,
                  in_flow->stats.src.packets,in_flow->stats.src.bytes,in_flow->stats.src.ip_flags,
                  in_flow->stats.src.tcp_flags,in_flow->stats.src.icmp_packets,in_flow->stats.src.icmp_seen,
                  in_flow->stats.dst.start_time,in_flow->stats.dst.start_msec,
                  in_flow->stats.dst.end_time,in_flow->stats.dst.end_msec,
                  in_flow->stats.dst.packets,in_flow->stats.dst.bytes,in_flow->stats.dst.ip_flags,
                  in_flow->stats.dst.tcp_flags,in_flow->stats.dst.icmp_packets,in_flow->stats.dst.icmp_seen,
                  (unsigned int) in_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32,
                
                  sensor_id,
                  flow_db_id
                   );

           result=dbi_conn_query(conn,query);
           rvalue=dbi_result_free(result);
#ifndef ADD_FLOW_PERF_STATS
//#define ADD_FLOW_PERF_STATS 
#endif

#ifdef ADD_FLOW_PERF_STATS

           if(in_flow->stats.end_time()==(unsigned int) in_flow->annot[FLOW_ANNOT_LAST_EMIT_SEC].as_int32){
                  //do update

               snprintf(query2, 2000,
                   "UPDATE flow_perf SET bytes=bytes+%u ,packets=packets+%u WHERE sensor_id=%u and flow_id=%u and sec=%u ",
                      in_flow->stats.bytes()  - (unsigned int) in_flow->annot[FLOW_ANNOT_LAST_BYTE_C].as_int32,
                      in_flow->stats.packets()- (unsigned int) in_flow->annot[FLOW_ANNOT_LAST_PACK_C].as_int32,
                      sensor_id,
                      flow_db_id,
                      in_flow->stats.end_time()
                      );
               }
           else{
               //curr_packet_size=annot[FLOW_ANNOT_SIG_PACK_SIZE].as_int32;
               if(in_flow->stats.bytes()  -  in_flow->annot[FLOW_ANNOT_LAST_BYTE_C].as_int32-in_flow->annot[FLOW_ANNOT_SIG_PACK_SIZE].as_int32 > 8000){
                  curr_packet_size=0;
               }
               else{
                  curr_packet_size=in_flow->annot[FLOW_ANNOT_SIG_PACK_SIZE].as_int32;
               }
                  //do update and insert
               if(0!= curr_packet_size | (in_flow->stats.packets()-in_flow->annot[FLOW_ANNOT_LAST_PACK_C].as_int32-1)  ){
                  snprintf(query, 1000,
                      "UPDATE flow_perf SET bytes=bytes+%u ,packets=packets+%u WHERE sensor_id=%u and flow_id=%u and sec=%u ",
                         in_flow->stats.bytes()  -  in_flow->annot[FLOW_ANNOT_LAST_BYTE_C].as_int32-curr_packet_size,
                         in_flow->stats.packets()-  in_flow->annot[FLOW_ANNOT_LAST_PACK_C].as_int32-1,
                         sensor_id,
                         flow_db_id,
                      in_flow->annot[FLOW_ANNOT_LAST_EMIT_SEC].as_int32
                       );
                  //fprintf(stderr,"flow_perf_q=%s\n",query);

                  result=dbi_conn_query(conn,query);
                  rvalue=dbi_result_free(result);
               }

               snprintf(query2, 2000,
		   " INSERT INTO flow_perf (sensor_id,flow_id,sec,bytes,packets) VALUES "
                   " (%u,%u,%u,%u,%u)",
                      sensor_id,
                      flow_db_id,
                      in_flow->stats.end_time(),
                      //in_flow->annot[FLOW_ANNOT_SIG_PACK_SIZE].as_int32,
                      curr_packet_size,
                      1
                      );
            }
           //fprintf(stderr,"flow_perf_q=%s\n",query);
           result=dbi_conn_query(conn,query2);
           rvalue=dbi_result_free(result);

#endif


        }
        else{
          //Not found, do a regular insert, but first free the result
           rvalue=dbi_result_free(result);

           snprintf(query, 10000,
                 "%s (%u,  %u,%u,%u,%u,%u,    %u,%u,%u,%u, %u,%u,%u,%u,%u,%u,%u,  %u,%u,%u,%u, %u,%u,%u,%u,%u,%u  )",
                  section1,
                  sensor_id,
                  in_flow->source_ip,in_flow->dest_ip,in_flow->src_port,in_flow->dst_port, in_flow->protocol,
                  in_flow->stats.src.start_time,in_flow->stats.src.start_msec,
                  in_flow->stats.src.end_time,in_flow->stats.src.end_msec,
                  in_flow->stats.src.packets,in_flow->stats.src.bytes,in_flow->stats.src.ip_flags,
                  in_flow->stats.src.tcp_flags,in_flow->stats.src.icmp_packets,in_flow->stats.src.icmp_seen,
                  in_flow->stats.dst.start_time,in_flow->stats.dst.start_msec,
                  in_flow->stats.dst.end_time,in_flow->stats.dst.end_msec,
                  in_flow->stats.dst.packets,in_flow->stats.dst.bytes,in_flow->stats.dst.ip_flags,
                  in_flow->stats.dst.tcp_flags,in_flow->stats.dst.icmp_packets,in_flow->stats.dst.icmp_seen,
                  (unsigned int) in_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32);

           result=dbi_conn_query(conn,query);
           rvalue=dbi_result_free(result);
 

#ifdef ADD_FLOW_PERF_STATS
           //find dbid
    /*
           snprintf(query,10000, "SELECT flow_id ,GREATEST(src_end_sec,dst_end_sec) as etime from flow "
                                            "WHERE sensor_id=%u AND ip_proto=%d AND "
                                            "src_ip=%u AND src_port=%d AND "
                                            "dst_ip=%d AND dst_port=%u AND "
                                            "src_start_sec=%u "
                                            "ORDER BY src_start_sec LIMIT 1",
                                            sensor_id, in_flow->protocol,
                                            in_flow->source_ip,in_flow->src_port,
                                            in_flow->dest_ip,in_flow->dst_port,
                                            in_flow->stats.src.start_time );
           result=dbi_conn_query(conn,query);

           if(!result){
              fprintf(stderr,"%s\n",query);
              perror("dbins-block: problem on query 0  "); exit(1);
            }
           if(dbi_result_next_row(result)) {
             //found==true!!
             flow_db_id=dbi_result_get_long(result, "flow_id");
             rvalue=dbi_result_free(result);
      */     
             //now do perf insert
             snprintf(query2, 22000,
/*
                   "INSERT INTO flow_perf (sensor_id,flow_id,sec,bytes,packets) VALUES "
                   " (%u,%u,%u,%u,%u)",
                      sensor_id,
                      flow_db_id,
*/
                   "INSERT INTO flow_perf (sensor_id,flow_id,sec,bytes,packets) VALUES "
                   " (%u,LAST_INSERT_ID(),%u,%u,%u)",
                      sensor_id,
                      in_flow->stats.end_time(),
                      in_flow->stats.bytes()  - (unsigned int) in_flow->annot[FLOW_ANNOT_LAST_BYTE_C].as_int32,
                      in_flow->stats.packets()- (unsigned int) in_flow->annot[FLOW_ANNOT_LAST_PACK_C].as_int32
                      );
             //fprintf(stderr,"flow_perf_q=%s\n",query);


             result=dbi_conn_query(conn,query2);
             rvalue=dbi_result_free(result);
       /*
           }
           else{
             fprintf(stderr,"flow_perf.. WTF.. previous inserted not found! \nquery=%s\n",query);
           }
*/

#endif
	}


   }
   else{ //the dbid is known do an update
        //then select and store the content in the flow annot!
        snprintf(query,10000, "UPDATE flow set src_end_sec=%u, src_end_msec=%u,"
                              "src_packets",rvalue,rvalue);
        //db_id_added_to_flow=true;
        cout <<"NOT DONE YET!!"<<endl;
   }

   return 0;  
}

///////
int Flow_DB_Inserter_Block::db_flow_insert_mysql(Tagged_IPV4_Flow *in_flow){//should be renamed mysql insert!!
   static char *section1="INSERT INTO flow"
                "(sensor_id, "
                " src_ip,dst_ip,src_port,dst_port,ip_proto,"
                " src_start_sec,src_start_msec,src_end_sec,src_end_msec,"
                " src_packets,src_bytes,src_ip_flags,src_tcp_flags,src_icmp_packets,src_icmp_seen,"
                " dst_start_sec,dst_start_msec,dst_end_sec,dst_end_msec,"
                " dst_packets,dst_bytes,dst_ip_flags,dst_tcp_flags,dst_icmp_packets,dst_icmp_seen, "
                " marker_flags) "
                " VALUES ";
   //static char *section2=" ON DUPLICATE KEY UPDATE SET ";
   int rvalue=-1;
   //static char *flow_id_query;
   char query[10000];
   char query2[2000]; 
   //char added[10000];
   dbi_result result;
   unsigned int flow_db_id; 
   unsigned int last_time;
   unsigned int curr_packet_size;
  
   db_id_added_to_flow=false;

   if (0==in_flow->annot[FLOW_ANNOT_DB_ID].as_int32){ //no db id known, do an insert

        snprintf(query, 10000,
                 "%s (%u,  %u,%u,%u,%u,%u,    %u,%u,%u,%u, %u,%u,%u,%u,%u,%u,%u,  %u,%u,%u,%u, %u,%u,%u,%u,%u,%u  )"
                 " ON DUPLICATE KEY UPDATE src_end_sec=%u,src_end_msec=%u,"
                 "src_packets=%u,src_bytes=%u,src_ip_flags=%u,src_tcp_flags=%u,src_icmp_packets=%u,src_icmp_seen=%u,"
                 "dst_start_sec=%u,dst_start_msec=%u,dst_end_sec=%u,dst_end_msec=%u,"
                 "dst_packets=%u,dst_bytes=%u,dst_ip_flags=%u,dst_tcp_flags=%u,dst_icmp_packets=%u,dst_icmp_seen=%u,"
                 "marker_flags=%u",
                  section1,
                  sensor_id,
                  in_flow->source_ip,in_flow->dest_ip,in_flow->src_port,in_flow->dst_port, in_flow->protocol,
                  in_flow->stats.src.start_time,in_flow->stats.src.start_msec,
                  in_flow->stats.src.end_time,in_flow->stats.src.end_msec,
                  in_flow->stats.src.packets,in_flow->stats.src.bytes,in_flow->stats.src.ip_flags,
                  in_flow->stats.src.tcp_flags,in_flow->stats.src.icmp_packets,in_flow->stats.src.icmp_seen,
                  in_flow->stats.dst.start_time,in_flow->stats.dst.start_msec,
                  in_flow->stats.dst.end_time,in_flow->stats.dst.end_msec,
                  in_flow->stats.dst.packets,in_flow->stats.dst.bytes,in_flow->stats.dst.ip_flags,
                  in_flow->stats.dst.tcp_flags,in_flow->stats.dst.icmp_packets,in_flow->stats.dst.icmp_seen,
                  (unsigned int) in_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32,

                  in_flow->stats.src.end_time,in_flow->stats.src.end_msec,
                  in_flow->stats.src.packets,in_flow->stats.src.bytes,in_flow->stats.src.ip_flags,
                  in_flow->stats.src.tcp_flags,in_flow->stats.src.icmp_packets,in_flow->stats.src.icmp_seen,
                  in_flow->stats.dst.start_time,in_flow->stats.dst.start_msec,
                  in_flow->stats.dst.end_time,in_flow->stats.dst.end_msec,
                  in_flow->stats.dst.packets,in_flow->stats.dst.bytes,in_flow->stats.dst.ip_flags,
                  in_flow->stats.dst.tcp_flags,in_flow->stats.dst.icmp_packets,in_flow->stats.dst.icmp_seen,
                  (unsigned int) in_flow->annot[FLOW_ANNOT_MARKER_FLAGS].as_int32
                   );
        result=dbi_conn_query(conn,query);
        
        rvalue=dbi_result_free(result);  
        //cout<<"inserting: "<< query<<endl;






   }
   else{ //the dbid is known do an update
        //then select and store the content in the flow annot!
        snprintf(query,10000, "UPDATE flow set src_end_sec=%u, src_end_msec=%u,"
                              "src_packets",rvalue,rvalue);
        //db_id_added_to_flow=true;
        cout <<"NOT DONE YET!!"<<endl;
   }

   return 0;  
}


#endif




