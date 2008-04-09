// (C) 2006-2007 The Trustees of Indiana University.  All rights reserved.
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

#include "config.h"

#include <unistd.h>
#include <iostream>
#include <stdlib.h>
#include <pwd.h>

#include "element.h"
#include "frag_drop.hpp"
#include "pcap_ipv4_infile_block.hpp"
#include "pcap_outfile_block.hpp"
#include "active_ipv4_flow_db.hpp"
#include "bidir_flow_maker_block.hpp"
#include "ulog_live_ipv4_block.hpp"
#include "flow_db_inserter_block.hpp"
#include "hflow_sebek_block.hpp"
#include "snort_block.hpp"
#include "p0f_block.hpp"
#include "pcre_flow_tagger_block.hpp"
#include "marker_filter_block.hpp"
#include "bpf_filter_block.hpp"
#include "entropy_flow_tagger_block.hpp"
//#include "bidir_performance_block.hpp"

#include <signal.h>
#include <errno.h>
#include <stdio.h>


using namespace std;

#define MAX_NAME_LENGTH


/*This is a small demo of what can be potentially be done with the flow stuff, this
is a very basic flow maker, has 3 types of inputs and a forced known db output.. (hey I am lazy
sometimes

to compile:
   g++ -O2 -o hflow2 hflow2.cpp -lpthread -lpcap -ldl -ldbi

*/



int usage(){
  printf("usage: hflow  [-i devname|-r filename |-u ulogtargetnum [-E]]\n"
         "              [-w outfilename [-l size_limit]]\n"
         "              [-d num [-s sensor_num]]\n"
         "              [-D]\n"
         "              [-z username] \n"
         "              [-f bpf_filter]\n\n");
  printf("must include at least one input type and for live options no partial data is printed for now\n");
  return 0;
}

int version_info(){
  printf("%s version %s\n", PACKAGE, VERSION);
  return usage();
}

void sigint_handler(int sig)
    {
        printf("SIG TERM  Received, exiting!\n");
        exit(1);
    }

void parent_sig_handler(int sig)
    {
        printf("Hflow: premature failure. Initialization aborted?\n"
               "Parent sighandler, something  Received, exiting!\n");
        exit(1);
    }



int main(int argc,char **argv)
{
 //Frag_Drop drop1;
 Tagged_IP_Packet packet1;
 //Processing_Block *input_block;
 Pcap_IPv4_Infile_Block pcap_in;
 Pcap_Outfile_Block pcap_out;
 Bidir_Flow_Maker_Block flow_maker;
 Null_Processing_Block null_block;
 Ulog_Live_IPv4_Block ulog_in;
 Flow_DB_Inserter_Block db_inserter;
 Hflow_Sebek_Block sebek_block;
 Snort_Block snort_block;
 Pcre_Flow_Tagger pcre_block;
 Marker_Filter_Block marker_filter_block;
 Entropy_Flow_Tagger_Block entropy_block;
 p0f_Block p0f_block;
 BPF_Filter bpf_filter;

 char *outname=NULL;
 char *inname=NULL;
 int input_type=-1;
 int num_inputs=0;
 bool use_db=false;
 bool daemon_mode=false;
 bool use_snort=true;
 int file_limit=0;
 int r;
 char file_extension[10]="\0";
 pid_t pid, sid;
 char *base_log_filename="hflowd.log";
 char log_filename[256];
 char *log_dir=NULL;
 char *conf_dir=NULL;
 //char empty_string[2]="\0";
 int log_fd;
 unsigned int sensor_id=0;
 char *database_type="mysql";
 char *database_name="hflow";
 char *database_user="hflowdaemon";
 char *database_password="";
 char *bpf_filter_string=NULL;
 //char full_log_filename[256];
 char *default_logdir=".";
 char *pid_filename=NULL;
 bool use_pid_file=false;
 FILE *pid_file;
 char *run_username=NULL;
 struct passwd *pw;
 uint16_t sebek_dst_port=1101;

       /* set up the handler */
        if (signal(SIGINT, sigint_handler) == SIG_ERR) {
            perror("signal");
            exit(1);
        }

 log_dir=default_logdir;
 conf_dir=default_logdir; 
 //cout << "hello world"<<endl;

 //get options and initialize the variables
 while ((r = getopt(argc, argv, "hVDSTi:r:u:w:d:E:l:s:f:L:C:z:p:k:")) != -1){

      switch(r){
        case 'V':version_info();
                 return 0;
                 break;  
        case 'h':usage();
                 return 0;
                 break; 
        case 'D':daemon_mode=true;
                 break; 
        case 'T':marker_filter_block.drop_long=true;
                 break;
        case 'r':inname=optarg;
                 num_inputs++;
                 input_type=0;
                 break;   
        case 'i':inname=optarg;
                 num_inputs++;
                 input_type=1;
                 break;
        case 'u':inname=optarg;
                 num_inputs++;
                 input_type=2;
                 break;
        case 'w': outname=optarg; break;
        case 'd': use_db=true; break;
        case 'E': ulog_in.set_linktype(DLT_EN10MB); break;
        case 'l': file_limit=atoi(optarg);
                  if(file_limit>1000 || file_limit<3) file_limit=100;
                  break;
        case 's': sensor_id=atoi(optarg);
                  #ifdef VERBOSE
                  printf("sensor_id=%d\n",sensor_id);
                  #endif
                  break;
        case 'f': bpf_filter_string=optarg;
                  break;
        case 'L': log_dir=optarg;
                  break;
        case 'C': conf_dir=optarg;
                  break;
        case 'S': use_snort=false;
                  break;
        case 'z': run_username=optarg;
                  break;
        case 'p': pid_filename=optarg;
                  use_pid_file=true;
                  break;
        case 'k': sebek_dst_port=atoi(optarg);
                  break;

        }
 }
 //check options and send user to usage if something is not quite correct
 if(num_inputs!=1){
    usage();
    exit(1);
 }
 //some sanity checks
 if(NULL==pid_filename && true==use_pid_file){
     usage();
     exit(1);   
 };

 //go and deamonize this guy.. 
 if (true==daemon_mode){
      //sanity checks.....
      if(inname!=NULL){
         if(0==strcmp("-",inname)){
             fprintf(stderr,"Sorry, cannot be in deamon mode AND read from stdin\n");
             exit(1);
         }
      }
      if(outname!=NULL){
         if(0==strcmp("-",outname)){
             fprintf(stderr,"Sorry, cannot be in deamon mode AND write to stdout\n");
             exit(1);
         }
      }

      //now actual demoization workd
      pid = fork();
      if (pid < 0) {
            fprintf(stderr, "Demonization requested,"
                            " but cant Deamonize(error on fork)."
                            " Aborting execution\n");   
            exit(EXIT_FAILURE);
      }
      // If we got a good PID, then
      // we can exit the parent process.
      if (pid > 0) {
            //actually we should wait for a signal that 
            //everything seem to go ok before exiting 
 
            if (signal(SIGCHLD, parent_sig_handler) == SIG_ERR) {
                perror("signal");
                exit(1);
            }


            sleep(6);
            #ifdef VERBOSE
            fprintf(stdout, "looks like initialization was a success\n");   
            #endif

            exit(EXIT_SUCCESS);
      }
      sid = setsid();
      if (sid < 0) {
                /* Log any failure */
                fprintf(stderr, "Demonization requested,"
                            " but cant Deamonize(error on setsid)."
                            " Aborting execution\n");

                exit(EXIT_FAILURE);
       }
       //generate log_filename
       snprintf(log_filename,254,"%s/%s",log_dir,base_log_filename);

       //open log file
       log_fd=open(log_filename, O_WRONLY|O_CREAT |O_TRUNC, (S_IRUSR | S_IWUSR | S_IRGRP|S_IROTH ) );
       if(0>log_fd){perror("Hflow main: Cannot open deamon log file");exit(1);}

       //redirect stderr and stout and redirect to log file      
       dup2(log_fd,2);
       //close(log_fd);
       dup2(log_fd,1);
       close(log_fd);       
 }
 

  
 //-------------------------------initialize objects
 // 
 //start with input
 switch(input_type){
     case 0: pcap_in.initialize(1,inname);
             break;
     case 1: pcap_in.initialize(1,inname,1);
             break;
     case 2: ulog_in.initialize(1,atoi(inname));
             break;
     default: printf("internal error, (unregnized input type)\n"); 
             exit(1);
             break;
 } 
 //input is done, try to change user;
 if(NULL!=run_username){
     if (geteuid()) {
        fprintf(stderr, "only root can use -u.\n");
        exit(1);
     }
     pw=getpwnam(run_username);
     if(NULL==pw){
        fprintf(stderr, "User %s not found.aborting\n",run_username);
        exit(1);
     }
     if(0!=setgid(pw->pw_gid) || 0!=setuid(pw->pw_uid)){
        perror("Could not change uid. aborting\n");
        exit(1);
     }
 }


 //now the generate the extension when using a limit
 if(0!=file_limit){
     snprintf(file_extension,10,"pcap");
 }

 //now the output
 if(NULL!=outname){
    if ((0==input_type) || (1==input_type)){
         //pcap_out.initialize(outname,pcap_in.get_linktype());
         pcap_out.initialize_with_rotate(outname,file_extension,file_limit,pcap_in.get_linktype());
         //bpf_filter.initialize(1,bpf_filter_string,pcap_in.get_linktype());
          
    }
    if (2==input_type) {
         //pcap_out.initialize(outname,ulog_in.get_linktype());
         pcap_out.initialize_with_rotate(outname,file_extension,file_limit,ulog_in.get_linktype());
         //bpf_filter.initialize(1,bpf_filter_string,ulog_in.get_linktype());

    }
    if(true==pcap_out.live_read) pcap_out.set_non_blocking();

 }
 if(NULL!=bpf_filter_string){
    switch(input_type){
        case 0:
        case 1:
           bpf_filter.initialize(1,bpf_filter_string,pcap_in.get_linktype());
           break;
        case 2:
           bpf_filter.initialize(1,bpf_filter_string,ulog_in.get_linktype());
           break;
    }
 }
 
 //initialize snort block first!!!(actually does not matter in linux/or solaris)
 //snort_block.initialize(1);
 if (use_snort){
   snort_block.set_log_dir(log_dir);
   snort_block.initialize(1,database_type,database_name,database_user,database_password,sensor_id);
 }

 //now the db(ok i need to add these to the init options)
 if(use_db){
    //db_inserter.initialize(1,"mysql","hflow","hflowdaemon","");
    db_inserter.initialize(1,database_type,database_name,database_user,database_password,sensor_id);
 };
 //finally the flow_maker.. this always is initialized in this app
 flow_maker.initialize(1);

 //sebek_block.initialize(1);
 sebek_block.set_dst_port(sebek_dst_port);
 sebek_block.set_flow_maker(&flow_maker);
 sebek_block.initialize(1,database_type,database_name,database_user,"",sensor_id);
 //snort_block.initialize(1);
 p0f_block.initialize(1,database_type,database_name,database_user,"",sensor_id);
  
 pcre_block.initialize(1); 
 marker_filter_block.initialize(1);
 entropy_block.initialize(1);

 fprintf(stderr,"initialization done!\n");

 //make links(connect lego blocks) 
 if(use_snort){
    flow_maker.set_output_point(&snort_block);
    //snort_block.set_output_point(&sebek_block);
 }
 else{
    flow_maker.set_output_point(&p0f_block);
 }
 snort_block.set_output_point(&p0f_block);
 p0f_block.set_output_point(&sebek_block);

 sebek_block.set_output_point(&marker_filter_block);
 //sebek_block.set_output_point(&pcre_block);
 //sebek_block.set_output_point(&entropy_block);

// pcre_block.set_output_point(&marker_filter_block);
 pcre_block.set_output_point(&entropy_block);
 entropy_block.set_output_point(&marker_filter_block);
 //out only if filename
 if(NULL!=outname){
    marker_filter_block.set_output_point(&pcap_out);
 }
 bpf_filter.set_output_point(&flow_maker);
 if(bpf_filter.is_valid()){
    pcap_in.set_output_point(&bpf_filter);
    ulog_in.set_output_point(&bpf_filter);
    }
 else{
    pcap_in.set_output_point(&flow_maker);
    ulog_in.set_output_point(&flow_maker);
    }
 if (use_db)flow_maker.set_flow_output_point(&db_inserter);

 //----------------------------------------------------------------------------
 //initialization finished here

 //now make the pid file
 if(use_pid_file){
   pid_file=fopen(pid_filename,"w+");
   if(NULL==pid_file){
    perror("cannot create pid file, aborting\n");
    exit(1);
    }
    fprintf(pid_file,"%u",getpid());
    fclose(pid_file);
 }

 //startup system, 
 //       live collection will not result in functions returning.
 switch(input_type){
   case 0:
   case 1:
       pcap_in.entry_point(&packet1); 
       break;
   case 2: ulog_in.entry_point(&packet1); 
       break;
 }

 flow_maker.emit_all_flows(); //just a nice way to ensure db drop for offline inputs
 sleep(2);
 cout <<"finished ok" <<endl;
 //sleep(10);
 return 0;
}

