// (C) 2007 The Trustees of Indiana University.  All rights reserved.
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



#include <unistd.h>
#include <iostream>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>

#ifndef EXIT_ON_WRITE_FAIL
#define EXIT_ON_WRITE_FAIL
#endif

#include "element.h"
#include "bpf_filter_block.hpp"
#include "pcap_outfile_block.hpp"
#include "pcap_raw_infile_block.hpp"
#include "ulog_live_ipv4_block.hpp"


int version_info(){
    fprintf(stderr,"packet_capture version 0.0.1\n");
    return 0;
}

int usage(){
    version_info();
    fprintf(stderr,"A packet capture system\n\n");
    fprintf(stderr,"packet_capture [options] (-r INFILE | -i IFACE | -u ULOGID) -w OUTFILE \n\n");
    fprintf(stderr,"\t -D\t Deamonize\n");
    fprintf(stderr,"\t -V\t Display Version Information\n");
    fprintf(stderr,"\t -h\t Show help file\n");
    fprintf(stderr,"\t -l SIZE\t Limit file length to SIZE on MB\n");
    fprintf(stderr,"\t -f BPF_EXPR\t Process input trough the BPF_EXPR \n");
    fprintf(stderr,"\n");
    
    return 0;
}


void sigint_handler(int sig)
    {
        printf("SIG TERM  Received, exiting!\n");
        exit(1);
    }

void parent_sig_handler(int sig)
    {
        printf("packet_capture: premature failure. Initialization aborted?\n"
               "Parent sighandler, something  Received, exiting!\n");
        exit(1);
    }




int main(int argc,char **argv){
 Tagged_IP_Packet packet1;
 Pcap_Raw_Infile_Block pcap_in;
 Pcap_Outfile_Block pcap_out;
 Ulog_Live_IPv4_Block ulog_in;
 BPF_Filter bpf_filter;



 char *outname=NULL;
 char *inname=NULL;
 bool daemon_mode=false;
 pid_t pid, sid;
 int log_fd;
 int file_limit=0;
 char *log_filename="packet_capture.log";
 char *bpf_filter_string=NULL;
 int r;
 int num_inputs=0;
 int input_type=-1;
 char file_extension[10]="\0";



 /* set up the handler */
 if (signal(SIGINT, sigint_handler) == SIG_ERR) {
            perror("signal");
            exit(1);
 }



//get options and initialize the variables
 while ((r = getopt(argc, argv, "hVDEi:r:u:w:l:f:")) != -1){
      switch(r){
        case 'V':version_info();
                 return 0;
                 break;
        case 'h':usage();
                 return 0;
                 break;
        case 'D':daemon_mode=true;
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
        case 'E': ulog_in.set_linktype(DLT_EN10MB); break;
        case 'l': file_limit=atoi(optarg);
                  if(file_limit>1000 || file_limit<3) file_limit=100;
                  break;
        case 'f': bpf_filter_string=optarg;
                  break;
        }
 }
 //check options and send user to usage if something is not quite correct
 if(num_inputs!=1 || NULL==outname){
    usage();
    exit(1);
 }
 if(0!=file_limit && (0==strcmp("-",outname))){
          fprintf(stderr,"Sorry, cannot be put to stdout AND use file limits\n");
          exit(1);

      }



 //daemonization
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


            sleep(1);
            fprintf(stdout, "looks like initialization was a success\n");

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

       //open log file
       log_fd=open(log_filename, O_WRONLY|O_CREAT |O_TRUNC, (S_IRUSR | S_IWUSR | S_IRGRP|S_IROTH ) );
       if(0>log_fd){perror("packet_capture main: Cannot open deamon log file");exit(1);}

       //redirect stderr and stout and redirect to log file
       dup2(log_fd,2);
       //close(log_fd);
       dup2(log_fd,1);
       close(log_fd);
 }

 /// now do work
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
 //now the generate the extension when using a limit
 if(0!=file_limit){
     snprintf(file_extension,10,"pcap");
 }


 //now the output
 if(NULL!=outname){
    if ((0==input_type) || (1==input_type)){
         //pcap_out.initialize(outname,pcap_in.get_linktype());
         pcap_out.initialize_with_rotate(outname,file_extension,file_limit,pcap_in.get_linktype());
         bpf_filter.initialize(1,bpf_filter_string,pcap_in.get_linktype());

    }
    if (2==input_type) {
         //pcap_out.initialize(outname,ulog_in.get_linktype());
         pcap_out.initialize_with_rotate(outname,file_extension,file_limit,ulog_in.get_linktype());
         bpf_filter.initialize(1,bpf_filter_string,ulog_in.get_linktype());

    }
 }
 //check for error on bpf filter!
 if(bpf_filter.is_valid() && NULL!=bpf_filter_string){
    fprintf(stderr,"There is an error on the bpf filter expresion '%s'\n aborting \n",bpf_filter_string);
    exit(1);
 } 

 //--------now link everyone
 bpf_filter.set_output_point(&pcap_out);
  if(bpf_filter.is_valid()){
    pcap_in.set_output_point(&bpf_filter);
    ulog_in.set_output_point(&bpf_filter);
    }
 else{
    pcap_in.set_output_point(&pcap_out);
    ulog_in.set_output_point(&pcap_out);
    }

 //and finially initialize
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

 return 0;
}
