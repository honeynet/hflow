#ifndef ULOG_IPV4_INFILE_BLOCK_HPP
#define ULOG_IPV4_INFILE_BLOCK_HPP

/*
 * Contains portions of libpulog.h v1.02 , but placed here to avoid an extra dependency
 * on a non standard library. Also to prevent changes dues to a very young
 * and not very established API.
 * the whole exercise is to avoid dependencies.
 *
 * (C) 2000-2001 by Harald Welte <laforge@gnumonks.org>
 * (C) 2006 Camilo Viecco, The Trutees of Indiana University
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
*/



#include "element.h"
#include "l2_helpers.hpp"
#include <pcap.h>
#include <map>
#include <list>
#include <iostream>
#include <stdio.h>
//#include <libpulog/libpulog.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <linux/netfilter_ipv4/ipt_ULOG.h>

using namespace std;

#define ULOG_BUFF_SIZE 150000

////more defs, copied form libpulog
enum
{
        IPULOG_ERR_NONE = 0,
        IPULOG_ERR_IMPL,
        IPULOG_ERR_HANDLE,
        IPULOG_ERR_SOCKET,
        IPULOG_ERR_BIND,
        IPULOG_ERR_RECVBUF,
        IPULOG_ERR_RECV,
        IPULOG_ERR_NLEOF,
        IPULOG_ERR_TRUNC,
        IPULOG_ERR_INVGR,
        IPULOG_ERR_INVNL,
};
#define IPULOG_MAXERR IPULOG_ERR_INVNL

struct ipulog_handle
{
        int fd;
        u_int8_t blocking;
        struct sockaddr_nl local;
        struct sockaddr_nl peer;
        struct nlmsghdr* last_nlhdr;
};


struct ipulog_errmap_t
{
        int errcode;
        char *message;
} ipulog_errmap[] =
{
        { IPULOG_ERR_NONE, "No error" },
        { IPULOG_ERR_IMPL, "Not implemented yet" },
        { IPULOG_ERR_HANDLE, "Unable to create netlink handle" },
        { IPULOG_ERR_SOCKET, "Unable to create netlink socket" },
        { IPULOG_ERR_BIND, "Unable to bind netlink socket" },
        { IPULOG_ERR_RECVBUF, "Receive buffer size invalid" },
        { IPULOG_ERR_RECV, "Error during netlink receive" },
        { IPULOG_ERR_NLEOF, "Received EOF on netlink socket" },
        { IPULOG_ERR_TRUNC, "Receive message truncated" },
        { IPULOG_ERR_INVGR, "Invalid group specified" },
        { IPULOG_ERR_INVNL, "Invalid netlink message" },
};



//////////////////Class definition

class Ulog_Live_IPv4_Block: public Processing_Block{
  private:
    char errbuf[PCAP_ERRBUF_SIZE];
    int offset_to_ipv4_header;
    int offset_to_hdlc_type;
    bool const_offset;
    int linktype;
    //
    struct ipulog_handle *ulog_handle;
    char pktbuff[ULOG_BUFF_SIZE];
    int errors;
    bool copy_mac;
    char packet_copy[MAX_PACKET_PAYLOAD_LENGTH];

  public:
    bool with_loop;
    Tagged_IP_Packet out_packet;
  public:
    inline int entry_point(const Tagged_Element *in_packet){return entry_point((Tagged_IP_Packet *) in_packet);};
    int entry_point(const Tagged_IP_Packet *in_packet);
    int set_output_point(Processing_Block *out_block);
    int set_output_point(Processing_Block *,int out_index);
    int get_linktype(){return linktype;};
    int set_linktype(int intype){if(DLT_RAW!=intype) copy_mac=true; 
                                 else copy_mac=false;
                                 linktype=intype;
                                 return linktype;}
    int initialize(int numoutputs,unsigned char);
    Ulog_Live_IPv4_Block();
    ~Ulog_Live_IPv4_Block();
//copied defs....
    int ipulog_errno;//= IPULOG_ERR_NONE;

//copied funcs
  private:
    ssize_t ipulog_netlink_recvfrom(const struct ipulog_handle *h,
                        unsigned char *buf, size_t len);
  public:
    char *ipulog_strerror(int errcode);
    u_int32_t ipulog_group2gmask(u_int32_t group);
    struct ipulog_handle *ipulog_create_handle(u_int32_t gmask,
                                           u_int32_t rcvbufsize);
    void ipulog_destroy_handle(struct ipulog_handle *h);
    ssize_t ipulog_read(struct ipulog_handle *h, unsigned char *buf,
                    size_t len, int timeout);
    ulog_packet_msg_t *ipulog_get_packet(struct ipulog_handle *h,
                                     const unsigned char *buf,
                                     size_t len);
    void ipulog_perror(const char *s);

};

////////Class implementation
Ulog_Live_IPv4_Block::~Ulog_Live_IPv4_Block(){
   if(NULL!=ulog_handle){
     ipulog_destroy_handle(ulog_handle);
   }
};

Ulog_Live_IPv4_Block::Ulog_Live_IPv4_Block(){
   initialized=false;
   copy_mac=false;
   linktype=DLT_RAW;
   next_stage=NULL;
   num_outputs=0;
   ulog_handle=NULL;
   ipulog_errno = IPULOG_ERR_NONE;
   errors=0;
};


int Ulog_Live_IPv4_Block::initialize(int in_numoutputs,unsigned char group){
  int i;

  next_stage =new Processing_Block*[in_numoutputs];
  num_outputs=in_numoutputs;
  for(i=0;i<num_outputs;i++){
     next_stage[i]=NULL;   
  }  
  //open ulog
  ulog_handle=ipulog_create_handle(ipulog_group2gmask(group),ULOG_BUFF_SIZE);
  if(!ulog_handle){
       ipulog_perror(NULL);
       exit(1);
  }
  
  live_read|=true;
 
  initialized=true;
  valid_outputs=0;
  return 0; 
};


int Ulog_Live_IPv4_Block::entry_point(const Tagged_IP_Packet *in_packet){
  
  //cout << "inpacket" <<endl;
   ///processs here .. will always do loop for now
     //Do pcap loop here
  //return pcap_loop(pcap_descr,-1,call_back_entry_point,(u_char *)this);
  int len;
  ulog_packet_msg_t *upkt;  
  struct pcap_pkthdr pcap_hdr;
  int i;
  int j=0;
  //u_char *local;

  while(1 && j<80){
     //cout << ".";
     len=ipulog_read(ulog_handle,(unsigned char *) pktbuff,ULOG_BUFF_SIZE,1);
     if(len<=0){
           ipulog_perror("ulog_test: short read");
           //return -1;
           cout << "errno=" <<errno;
           exit(1);
          
     }
     else{
        out_packet.pcap_hdr=&pcap_hdr;
        while(upkt=ipulog_get_packet(ulog_handle,(unsigned char *)pktbuff,len)){
            pcap_hdr.ts.tv_sec =upkt->timestamp_sec;
            pcap_hdr.ts.tv_usec=upkt->timestamp_usec;
            if (copy_mac){
               pcap_hdr.caplen=upkt->data_len-sizeof(struct ulog_packet_msg); //not quite?
               pcap_hdr.caplen=upkt->data_len+upkt->mac_len;
               pcap_hdr.len=0;  //this is not true, but how else to specify unkown?
               pcap_hdr.len=pcap_hdr.caplen;
               memcpy(packet_copy,upkt->mac,upkt->mac_len);
               memcpy((void *) (&packet_copy[upkt->mac_len]),
                                     upkt->payload,upkt->data_len);
               out_packet.data=(u_char *)packet_copy;
               out_packet.pcap_hdr=&pcap_hdr;
               //fprintf(stderr,"mac_len=%d in_dev_name=%s\n",upkt->mac_len,upkt->indev_name);
               //do something!!!
               //check for ipv4?
               out_packet.ip_header_offset=upkt->mac_len;
            }
            else{
               pcap_hdr.caplen=upkt->data_len-sizeof(struct ulog_packet_msg); //not quite?
               pcap_hdr.caplen=upkt->data_len;
               pcap_hdr.len=0;  //this is not true, but how else to specify unkown?
               pcap_hdr.len=pcap_hdr.caplen;
               out_packet.data=upkt->payload;
               out_packet.pcap_hdr=&pcap_hdr;
               //fprintf(stderr,"mac_len=%d in_dev_name=%s\n",upkt->mac_len,upkt->indev_name);
               //do something!!!
               //check for ipv4?
               out_packet.ip_header_offset=0;
               }
            //put iface info here...
            //we assume(badly) that all iface names have 3 letters before a number..
            out_packet.annot[PACKET_ANNOT_IFACE_ID].as_ptr=(void *)(atoi(upkt->indev_name+3)|0x80000000);

            //need to verify ipv4 here!!
        

            for(i=0;i<valid_outputs;i++){///ok I will use a cast for now, but I
                                      //am not sure of its correctness
                     (next_stage[i])->entry_point(&out_packet);
                 }
        }//closes while
     }
     j++;
  }
  return 0;
}

////////////////////
int Ulog_Live_IPv4_Block::set_output_point(Processing_Block *out_block){
   
  if (false==initialized){
     return -1;
  }
  next_stage[0]=out_block;
  if (valid_outputs<1){
     valid_outputs=1;
  };
  return 0;
};
///////////////////////////////////
//---------------now copied implementations
///////////////////////////////////////


ssize_t
Ulog_Live_IPv4_Block::ipulog_netlink_recvfrom(const struct ipulog_handle *h,
                        unsigned char *buf, size_t len)
{
        socklen_t addrlen;
        int status;
        //int addrlen, status;
        struct nlmsghdr *nlh;

        if (len < sizeof(struct nlmsgerr)) {
                ipulog_errno = IPULOG_ERR_RECVBUF;
                return -1;
        }
        addrlen = sizeof(h->peer);
        status = recvfrom(h->fd, buf, len, 0, (struct sockaddr *)&h->peer,
                        &addrlen);
        if (status < 0)
        {       
                cout << "negative status error?" <<endl;
                cout << "len= " <<len << " addrlen= "<<(int)addrlen<<" status="<<status<<endl;
                ipulog_errno = IPULOG_ERR_RECV;
                return status;
        }
        if (addrlen != sizeof (h->peer))
        {
                cout << "sizeof h->peer? what is this?"<<endl;
                ipulog_errno = IPULOG_ERR_RECV;
                return -1;
        }
        if (status == 0)
        {
                cout <<"closing connection? wtf!!"<<endl;
                ipulog_errno = IPULOG_ERR_NLEOF;
                return -1;
        }
        nlh = (struct nlmsghdr *)buf;
        if (nlh->nlmsg_flags & MSG_TRUNC || 
                   status > (int)len)  //int cast added by cviecco.. problematic
        {
                ipulog_errno = IPULOG_ERR_TRUNC;
                return -1;
        }
        return status;
}

/*public*/

char *Ulog_Live_IPv4_Block::ipulog_strerror(int errcode)
{
        if (errcode < 0 || errcode > IPULOG_MAXERR)
                errcode = IPULOG_ERR_IMPL;
        return ipulog_errmap[errcode].message;
}



/* convert a netlink group (1-32) to a group_mask suitable for create_handle */
u_int32_t Ulog_Live_IPv4_Block::ipulog_group2gmask(u_int32_t group)
{
        if (group < 1 || group > 32)
        {
                ipulog_errno = IPULOG_ERR_INVGR;
                return 0;
        }
        return (1 << (group - 1));
}

/* create a ipulog handle for the reception of packets sent to gmask */
struct ipulog_handle *Ulog_Live_IPv4_Block::ipulog_create_handle(u_int32_t gmask,
                                           u_int32_t rcvbufsize)

{
        struct ipulog_handle *h;
        int status;

        h = (struct ipulog_handle *) malloc(sizeof(struct ipulog_handle));
        if (h == NULL)
        {
                ipulog_errno = IPULOG_ERR_HANDLE;
                return NULL;
        }
        memset(h, 0, sizeof(struct ipulog_handle));
        h->fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_NFLOG);
        if (h->fd == -1)
        {
                ipulog_errno = IPULOG_ERR_SOCKET;
                close(h->fd);
                free(h);
                return NULL;
        }
        memset(&h->local, 0, sizeof(struct sockaddr_nl));
        h->local.nl_family = AF_NETLINK;
        h->local.nl_pid = getpid();
        h->local.nl_groups = gmask;
        status = bind(h->fd, (struct sockaddr *)&h->local, sizeof(h->local));
        if (status == -1)
        {
                ipulog_errno = IPULOG_ERR_BIND;
                close(h->fd);
                free(h);
                return NULL;
        }
        memset(&h->peer, 0, sizeof(struct sockaddr_nl));
        h->peer.nl_family = AF_NETLINK;
        h->peer.nl_pid = 0;
        h->peer.nl_groups = gmask;

        status = setsockopt(h->fd, SOL_SOCKET, SO_RCVBUF, &rcvbufsize,
                            sizeof(rcvbufsize));
        if (status == -1)
        {
                ipulog_errno = IPULOG_ERR_RECVBUF;
                close(h->fd);
                free(h);
                return NULL;
        }
        rcvbufsize=1;
        status = setsockopt(h->fd, SOL_SOCKET,  SO_KEEPALIVE, &rcvbufsize,
                            sizeof(rcvbufsize));


        return h;
}




/* destroy a ipulog handle */
void Ulog_Live_IPv4_Block::ipulog_destroy_handle(struct ipulog_handle *h)
{
        close(h->fd);
        free(h);
}




/* do a BLOCKING read on an ipulog handle */
ssize_t Ulog_Live_IPv4_Block::ipulog_read(struct ipulog_handle *h, unsigned char *buf,
                    size_t len, int timeout)
{
        return ipulog_netlink_recvfrom(h, buf, len);
}





/* get a pointer to the actual start of the ipulog packet,
   use this to strip netlink header */
ulog_packet_msg_t *Ulog_Live_IPv4_Block::ipulog_get_packet(struct ipulog_handle *h,
                                     const unsigned char *buf,
                                     size_t len)
{
        struct nlmsghdr *nlh;
        size_t remain_len;

        /* if last header in handle not inside this buffer,
         * drop reference to last header */
        if ((unsigned char *)h->last_nlhdr > (buf + len) ||
            (unsigned char *)h->last_nlhdr < buf) {
                h->last_nlhdr = NULL;
        }

        if (!h->last_nlhdr) {
                /* fist message in buffer */
                nlh = (struct nlmsghdr *) buf;
                if (!NLMSG_OK(nlh, len)) {
                        /* ERROR */
                        ipulog_errno = IPULOG_ERR_INVNL;
                        return NULL;
                }
        } else {
                /* we are in n-th part of multilink message */
                if (h->last_nlhdr->nlmsg_type == NLMSG_DONE ||
                    !(h->last_nlhdr->nlmsg_flags & NLM_F_MULTI)) {
                        /* if last part in multilink message,
                         * or no multipart message at all: return */
                        h->last_nlhdr = NULL;
                        return NULL;
                }

                /* calculate remaining lenght from lasthdr to end of buffer */
                remain_len = (len -
                                ((unsigned char *)h->last_nlhdr - buf));
                nlh = NLMSG_NEXT(h->last_nlhdr, remain_len);
        }

        h->last_nlhdr = nlh;

        return (ulog_packet_msg_t *)NLMSG_DATA(nlh);
}



/* print a human readable description of the last error to stderr */
void Ulog_Live_IPv4_Block::ipulog_perror(const char *s)
{
        if (s)
                fputs(s, stderr);
        else
                fputs("ERROR", stderr);
        if (ipulog_errno)
                fprintf(stderr, ": %s", ipulog_strerror(ipulog_errno));
        if (errno)
                fprintf(stderr, ": %s", strerror(errno));
        fputc('\n', stderr);
}





#endif
