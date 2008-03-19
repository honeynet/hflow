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


#ifndef PCAP_OUTFILE_BLOCK_HPP
#define PCAP_OUTFILE_BLOCK_HPP

#include "element.h"
#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

//next for rotary files
#include <time.h>  

//for non-block
#include "copy_packet.hpp"
#include <semaphore.h>
#include <signal.h>


#define PCAP_FILE_MAGIC 0xa1b2c3d4
#define PCAP_MAX_BASE_FILENAME 50

#define EXIT_ON_WRITE_FAIL


using namespace std;

//////////////////Class definition
class Pcap_Outfile_Block: public Processing_Block{
  private:
    struct pcap_file_header file_header;
    pcap_dumper_t *pcap_out_descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    char base_file_name[PCAP_MAX_BASE_FILENAME];
    char file_extension[PCAP_MAX_BASE_FILENAME/2];
    char filename[PCAP_MAX_BASE_FILENAME*2];
    unsigned int file_byte_limit;
    unsigned int current_size;
    bool do_rotate;
    bool blocking;
    int fd;
    static ssize_t Write(int fd, const void* buf,ssize_t count);
//----
    list <Copy_Packet> packet_queue;
    pthread_t pcap_outfile_processing_thread;
    pthread_mutex_t in_queue_mutex;
    sem_t queue_sem;
    sem_t done_sem;
    volatile bool input_done;
    struct timespec delay;


  public:
    inline int entry_point(const Tagged_Element *in_packet){return entry_point((Tagged_Packet *) in_packet);};
    int entry_point(const Tagged_Packet *in_packet);
    int initialize(const char *out_filename);
    int initialize(const char *out_filename,int linktype);
    int initialize_with_rotate(const char *base_name,const char *extension,int max_mb_size);
    int initialize_with_rotate(const char *base_name,const char *extension,int max_mb_size, int linktype);
    int initialize_on_open_fd(int in_fd,int linktype);
    int initialize_on_open_fd(int in_fd){return initialize_on_open_fd(in_fd,1);}
    int set_non_blocking(){blocking=false; return 0;}
    int write_packet(const Tagged_Packet *in_packet);
    int internal_collector();  //this is the non returning thread func
  //  Pcap_Outfile_Block(int link_type);
    Pcap_Outfile_Block();
    ~Pcap_Outfile_Block();
};

void *pcap_outfile_block_thread_func(void *inblock){
             Pcap_Outfile_Block *in_class;
             in_class=(Pcap_Outfile_Block *)inblock;
             in_class->internal_collector();
             return NULL;
};



////////Class implementation
Pcap_Outfile_Block::~Pcap_Outfile_Block(){
   int rvalue;
   input_done=true;

   fprintf(stderr,"pcap out block (%d): destroying pcap_out block\n",getpid());
   if(true==initialized && false==blocking){        rvalue=sem_post(&queue_sem);
      //aug 23: 8:30am .. there is still a race condition....
      // maybe change implementation of end function..
       if(0!=rvalue){perror("pcap out: error on queue post in destructor"); exit(1);};
       fprintf(stderr,"pcap out block (t:%u) before pthread join(%u)\n",pthread_self(),pcap_outfile_processing_thread);
       //rvalue=sem_wait(&done_sem);
       pthread_join(pcap_outfile_processing_thread,NULL);
       fprintf(stderr,"pcap outfile:after join\n");
       initialized=false;
       }
   //fprintf(stderr,"sebek block destroyed\n");


   if(fd>=0){close(fd);};
   fprintf(stderr,"pcap out block destroyed\n");

};

//Pcap_Outfile_Block::Pcap_Outfile_Block(){
//    Pcap_Outfile_Block::Pcap_Outfile_Block(1);  //default
//   };

Pcap_Outfile_Block::Pcap_Outfile_Block(){
   //cout <<"constructor"<<endl;
   file_header.magic=PCAP_FILE_MAGIC;
   file_header.version_major=2;
   file_header.version_minor=4;
   file_header.thiszone=0;  //change this, it is horrible!!!
   file_header.sigfigs=0;
   file_header.snaplen=MAX_PACKET_PAYLOAD_LENGTH;
   file_header.linktype=1;  //this is again wrong!!!  //1 is ethernet
   initialized=false;
   blocking=true;
   fd=-1;
   pcap_out_descr=NULL;
   current_size=0;
   do_rotate=false;
   base_file_name[0]=0;
   file_extension[0]=0;
   file_byte_limit=0;

   input_done=false;
   delay.tv_sec=0;
   delay.tv_nsec=0;

    //#added for test jan 24/2008
    int rvalue;
        rvalue=sem_init(&queue_sem,0, 0);
     if(-1==rvalue){perror("cannot initialize semaphore in pcap_out"); exit(1);}
 
 

   //cout << "const end"<<endl;
};


int Pcap_Outfile_Block::initialize_with_rotate(const char *base_name,const char *extension,int max_mb_size, int linktype)
{
 // char filename[PCAP_MAX_BASE_FILENAME*2];
  snprintf(base_file_name,PCAP_MAX_BASE_FILENAME,"%s",base_name);
  snprintf(file_extension,PCAP_MAX_BASE_FILENAME/2,"%s",extension);
  
  if(0!=max_mb_size){
     do_rotate=true;
  }
  file_byte_limit=(max_mb_size & 0x3FF) *1024*1024; //cant be larger that 2 gigs
  if(do_rotate){
     snprintf(filename,PCAP_MAX_BASE_FILENAME*2-1,"%s-%u.%s",base_file_name,(unsigned int)time(NULL),file_extension);
  }
  else{
     snprintf(filename,PCAP_MAX_BASE_FILENAME*2-1,"%s",base_file_name);
  }
  return initialize(filename,linktype);

}

int Pcap_Outfile_Block::initialize(const char *out_filename){
   return initialize(out_filename,file_header.linktype);
};

int Pcap_Outfile_Block::initialize(const char *out_filename,int linktype)
{ 

   file_header.linktype=linktype; 
   //cout << "in initialize with2 magic=" << file_header.magic<<endl;

   fd=open(out_filename, (O_RDWR | O_CREAT | O_TRUNC)  , S_IRUSR | S_IWUSR);
  
   if (fd<0){
       cout << "error opening file:" <<out_filename <<endl;
       exit(1);
   }
   return initialize_on_open_fd(fd,linktype);
};

int Pcap_Outfile_Block::initialize_on_open_fd(int in_fd, int linktype){
   int written;
   int rvalue;

   fd=in_fd;

   file_header.linktype=linktype;
   //write header
   written=Write(fd,&file_header,sizeof(struct pcap_file_header));
   if(sizeof(struct pcap_file_header)!=written){
      cout << "error writing to file" << endl;
      exit(1);
   }
   current_size=sizeof(struct pcap_file_header);
  
   if(false==initialized){
     fprintf(stderr,"pcap out:initializing comm structs\n");

     rvalue=pthread_mutex_init(&in_queue_mutex,NULL);
     if(0!=rvalue){perror("cannot initialize mutex in pcap_out"); exit(1);}

     rvalue=sem_init(&queue_sem,0, 0);
     if(-1==rvalue){perror("cannot initialize semaphore in pcap_out"); exit(1);}


     //create the new thread
     rvalue=pthread_create(&pcap_outfile_processing_thread,NULL,pcap_outfile_block_thread_func,(void*)this);
     if(0!=rvalue){perror("cannot create new thread in hflowsebek"); exit(1);};
     fprintf(stderr,"pcap_out block: new thread %u\n",pcap_outfile_processing_thread);

   }  

   initialized=true;

  return 0; 
};


inline int Pcap_Outfile_Block::write_packet(const Tagged_Packet *in_packet){
  struct portable_pcap_packet_hdr packet_header;
  size_t written;
  int old_fd;
  int blk=0;

  if(do_rotate && current_size>=file_byte_limit){
     //need to make new file...
      old_fd=fd;
      snprintf(filename,PCAP_MAX_BASE_FILENAME*2-1,"%s-%u.%s",base_file_name,(unsigned int)time(NULL),file_extension);
      initialize(filename);
      //if survived
      close(old_fd);
  }


  //write the header
 //need to convert for multiple portability...
  packet_header.ts.tv_sec=in_packet->pcap_hdr->ts.tv_sec;
  packet_header.ts.tv_usec=in_packet->pcap_hdr->ts.tv_usec;
  packet_header.caplen=in_packet->pcap_hdr->caplen;
  packet_header.len=in_packet->pcap_hdr->len;

  //written=Write(fd,in_packet->pcap_hdr,sizeof(struct pcap_pkthdr));
   written=Write(fd,&packet_header,sizeof(struct portable_pcap_packet_hdr));
  if(sizeof(struct portable_pcap_packet_hdr)!=written){
#ifdef EXIT_ON_WRITE_FAIL
     fprintf(stderr,"pcap out: fail to write pcap packet header, try%d len, got %d len\n",sizeof(struct portable_pcap_packet_hdr),written);
     exit(1);
#endif
      return -1;
   }
  //write the payload
  written=Write(fd,in_packet->data,in_packet->pcap_hdr->caplen);
  if(written!=in_packet->pcap_hdr->caplen){
#ifdef EXIT_ON_WRITE_FAIL
     fprintf(stderr,"pcap out: fail to write pcap packet data, try%d len, got %d len\n",in_packet->pcap_hdr->caplen,written);
     blk=blocking;
     fprintf(stderr,"pcap out: blocking=%d packet_header.caplen=%d\n",blk,packet_header.caplen);
     exit(1);
#endif
      return -1;
   }
  current_size+=sizeof(struct portable_pcap_packet_hdr)+written;
  //fprintf(stderr, "packet_written\n");
  return written+sizeof(struct portable_pcap_packet_hdr);

}

int Pcap_Outfile_Block::entry_point(const Tagged_Packet *in_packet){
  //this is blocking but I do not care...
  size_t written;
  int old_fd;
  int rvalue;
  struct timespec local_delay;
  struct portable_pcap_packet_hdr packet_header;

/*
  if(do_rotate && current_size>=file_byte_limit){
     //need to make new file...
      old_fd=fd;
      snprintf(filename,PCAP_MAX_BASE_FILENAME*2-1,"%s-%u.%s",base_file_name,(unsigned int)time(NULL),file_extension);
      initialize(filename);
      //if survived  
      close(old_fd);
  }
*/

  if(true==blocking) 
       return write_packet(in_packet);
  else{
      //fprintf(stderr,".");
      rvalue=pthread_mutex_lock(&in_queue_mutex);
      if(0!=rvalue){perror("pcap out: error on mutex lock, entry"); exit(1);};
      //fprintf(stderr,"-");
      packet_queue.push_back(*in_packet);
      local_delay=delay;
      rvalue=pthread_mutex_unlock(&in_queue_mutex);
      //fprintf(stderr,"/");

      if(0!=rvalue){perror("pcap out: error on mutex unlock, entry"); exit(1);};
      //set up signal for interal thread.
      rvalue=sem_post(&queue_sem);
      if(0!=rvalue){perror("pcap_out: error on queue post, entry"); exit(1);};

      if((local_delay.tv_nsec!=0) && (false==false)){
         rvalue=nanosleep(&delay,NULL);
         if(0!=rvalue){perror("pcap out: error on nanosleep, entry"); exit(1);};
      }
      //fprintf(stderr,",");

  }
     

/*
  //write the header
 //need to convert for multiple portability...
  packet_header.ts.tv_sec=in_packet->pcap_hdr->ts.tv_sec;
  packet_header.ts.tv_usec=in_packet->pcap_hdr->ts.tv_usec;
  packet_header.caplen=in_packet->pcap_hdr->caplen;
  packet_header.len=in_packet->pcap_hdr->len; 

  //written=Write(fd,in_packet->pcap_hdr,sizeof(struct pcap_pkthdr));
   written=Write(fd,&packet_header,sizeof(struct portable_pcap_packet_hdr));
  if(sizeof(struct portable_pcap_packet_hdr)!=written){
#ifdef EXIT_ON_WRITE_FAIL
     exit(1);
#endif
      return -1;
   }
  //write the payload
  written=Write(fd,in_packet->data,in_packet->pcap_hdr->caplen);
  if(written!=in_packet->pcap_hdr->caplen){
#ifdef EXIT_ON_WRITE_FAIL
     exit(1);
#endif
      return -1;
   }
  current_size+=sizeof(struct pcap_pkthdr)+written;
  //fprintf(stderr, "packet_written\n");
  return written+sizeof(struct pcap_pkthdr); 
*/ 

};

ssize_t Pcap_Outfile_Block::Write(int fd, const void* buf,ssize_t count){
  // Writes data to a fd, keeps attempting until all data is writen
  //  or the call fails. On interrupt, it is able to continue where it
  //  was interrupted.
  ssize_t written=0;
  ssize_t last_write;
  char *local_buf=(char*) buf;
  ssize_t last_err=0;
  do{
     last_write=write(fd,local_buf,count-written);
     if(-1==last_write && EINTR==errno){
        last_err=errno;
        last_write=0;
     }
     if(-1==last_write && EINTR !=errno){
        perror("write failed");
     }
     written+=last_write;
  }while((written<count) &&  ((last_write>0) || (last_err==EINTR)) );

  if(last_write<=0){
    perror("'Write' failed:");
    return last_write;
  }
  return written;
};


int Pcap_Outfile_Block::internal_collector(){
    //this is the body of the sebek processing section
   int rvalue;
   Copy_Packet *in_packet;
   list<Copy_Packet>::iterator packet_it;
   int list_size=0;
   int last_warn_size=0;
   struct timespec current_delay=delay;

  // return 0;

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
              perror("pcap out: error on sem_wat"); exit(1);
            };
          }while ((rvalue!=0) && (rvalue!=EINTR));

        if (true==input_done && 1>=list_size){goto normal_end;}

        //step2 get handle
        rvalue=pthread_mutex_lock(&in_queue_mutex);
        if(0!=rvalue){perror("pcap_out: error on mutex lock, collector"); exit(1);};
        in_packet=&(*packet_queue.begin());
        delay=current_delay;

        rvalue=pthread_mutex_unlock(&in_queue_mutex);
        if(0!=rvalue){perror("pcap out: error on mutex unlock, collector"); exit(1);};

        //setep 3 do db_insert
        //do_version3(in_packet);
        write_packet(in_packet);    
    
        #ifdef VERBOSE
        fprintf(stderr,".");
        #endif

        ///step 4 delete
        rvalue=pthread_mutex_lock(&in_queue_mutex);
        if(0!=rvalue){perror("pcap out: error on mutex lock, collector"); exit(1);};
        packet_queue.pop_front();
        list_size=packet_queue.size();
        rvalue=pthread_mutex_unlock(&in_queue_mutex);
        if(0!=rvalue){perror("pcap out: error on mutex unlock, collector"); exit(1);};

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
