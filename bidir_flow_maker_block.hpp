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



#ifndef BIDIR_FLOW_MAKER_HPP
#define BIDIR_FLOW_MAKER_HPP

#include "element.h"
#include <pcap.h>
#include "active_ipv4_flow_db.hpp"
#include <map>
#include <list>

#define BIDIR_FLOW_NUM_QUEUES 2

using namespace std;

typedef struct flow_pair_tag{
  Tagged_IPV4_Flow flow;
  int last_stats;
}Flow_Pair;

class LPF1{
  private:
     float filter_val;
     float filter_ratio;
  public:
     float get_filter_val(){return filter_val;};
     float update_filter(float inval){filter_val=filter_ratio*filter_val+(1-filter_ratio)*inval;
                                      return filter_val;};
     LPF1(){filter_ratio=0.995; filter_val=0;}
};

//////////////////Class definition
class Bidir_Flow_Maker_Block: public Processing_Block{
  private:
    static unsigned int active_flow_sec_limit;
    static unsigned int active_tcp_sec_limit;
    static unsigned int flow_sec_limit[BIDIR_FLOW_NUM_QUEUES];
    Processing_Block *flow_receiver;  
    map<Active_flow_indexer,list<Tagged_IPV4_Flow>::iterator> index;
    //map<Active_flow_indexer,list<Flow_Pair>::iterator> index;
    Null_Processing_Block default_flow_receiver;
    int last_old_check;   
    int inserted_in_last_sec;
    int num_olds_for_deletion;
    LPF1 old_rem_filter;
public:
    list<Tagged_IPV4_Flow> data_rep[BIDIR_FLOW_NUM_QUEUES];
    list<Flow_db_Tags> tag_list;

  
  public:
    inline int entry_point(const Tagged_Element *in_packet){return entry_point((Tagged_Packet *) in_packet);};
    int entry_point( Tagged_Packet *in_packet);
    int set_output_point(Processing_Block *out_block);
    int set_flow_output_point(Processing_Block *out_block);
    int initialize(int in_numoutputs);
    int DB_updater(Tagged_IP_Packet *in_packet);
    Bidir_Flow_Maker_Block();
    ~Bidir_Flow_Maker_Block();
    int emit_all_flows();
  private:
    inline int emit_old_or_update(Tagged_IPV4_Flow *dest, Tagged_IPV4_Flow *source,
                           Active_flow_indexer *current, unsigned int sec);
    int print_db();
    int print_index();
    int emit_old_and_delete(int up_to_n,unsigned int current_sec);
    int get_flow_class(Tagged_IPV4_Flow *inflow);
};
/////////////////////////////////////
////////Class implementation
////////////////////////////////////

unsigned int Bidir_Flow_Maker_Block::active_flow_sec_limit=630;
unsigned int Bidir_Flow_Maker_Block::active_tcp_sec_limit=630;
unsigned int Bidir_Flow_Maker_Block::flow_sec_limit[]={90,7220};
/////
Bidir_Flow_Maker_Block::~Bidir_Flow_Maker_Block(){
   list<Tagged_IPV4_Flow>::iterator pos;
   int i;
   cout << "final db values" <<endl;
   for(i=0;i<BIDIR_FLOW_NUM_QUEUES;i++){
      cout <<"rep " << i <<endl;
      pos=data_rep[i].begin();
      while(data_rep[i].end()!=pos){
         Flow_helpers::print_flow(&(*pos));
         pos++;
      }
   }
   //db insert
   //pos=data_rep.begin();
   //while(data_rep.end()!=pos){
   //   flow_receiver->entry_point(&(*pos));
   //   pos++;
   //}

   

};
//////
Bidir_Flow_Maker_Block::Bidir_Flow_Maker_Block(){
  initialized=false;
   next_stage=NULL;
   num_outputs=0;
   last_old_check=0;
   flow_receiver=&default_flow_receiver;
   inserted_in_last_sec=0;
   num_olds_for_deletion=0;
};

/////
int Bidir_Flow_Maker_Block::initialize(int in_numoutputs){
  int i;
  next_stage =new Processing_Block*[in_numoutputs];
  num_outputs=in_numoutputs;
  for(i=0;i<num_outputs;i++){
     next_stage[i]=NULL;
  }
  initialized=true;
  valid_outputs=0;
  return 0;
};

///////
int Bidir_Flow_Maker_Block ::entry_point( Tagged_Packet *in_packet){
  int i;
  Tagged_IP_Packet *local;
  int rvalue;
  int packet_count;
  Tagged_IPV4_Flow *flow;
  int last_flow_emit; //it would be nice to be unsigned, but tv_sec is signed!

  local=(Tagged_IP_Packet *)in_packet;

  //cout << "entry: index size="<<index.size() ;
  //cout << " data_repi[0].size= "<<data_rep[0].size()<<"data_repi[1].size= "<<data_rep[1].size()<<endl;


  //process..:  
  DB_updater(local);

  // call each valid output
  for(i=0;i<valid_outputs;i++){
      (next_stage[i])->entry_point(in_packet);
  }

  // now do magic emition part

  //call flow emiter
  if(in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr!=NULL){
      flow=(Tagged_IPV4_Flow *)in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr;
      packet_count=flow->stats.packets();
      last_flow_emit=(unsigned int)flow->annot[FLOW_ANNOT_LAST_EMIT_SEC].as_int32;
      if((packet_count<4) ||                                   
         (packet_count<16 && (packet_count & 0x1 ==0x1))||
         (packet_count<256 && (packet_count & 0xF ==0x1))||
         (last_flow_emit!=in_packet->pcap_hdr->ts.tv_sec) || 
         (packet_count & 0xFF)==0x1){ //period part
          //fprintf(stderr,"/");
          //if(last_flow_emit!=in_packet->pcap_hdr->ts.tv_sec){
          //    fprintf(stderr,".");
          //}
          //annotate signaler!
          flow->annot[FLOW_ANNOT_SIG_PACK_SIZE].as_int32=(in_packet->pcap_hdr->len-local->ip_header_offset-20);

          //send the flow!
          flow_receiver->entry_point(flow);
          flow->annot[FLOW_ANNOT_LAST_EMIT_SEC].as_int32=in_packet->pcap_hdr->ts.tv_sec;  //ugly        
          flow->annot[FLOW_ANNOT_LAST_PACK_C].as_int32=flow->stats.packets();
          flow->annot[FLOW_ANNOT_LAST_BYTE_C].as_int32=flow->stats.bytes();

      }
  }

  //delete old (maybe call the flowemiter again!)
  if(live_read || true){
      if(last_old_check!=in_packet->pcap_hdr->ts.tv_sec){
          num_olds_for_deletion=2+(int)(2*old_rem_filter.update_filter(inserted_in_last_sec));
          //cout << "to delete "<< num_olds_for_deletion<<endl;
          //emit_old_and_delete(4,in_packet->pcap_hdr->ts.tv_sec);
          inserted_in_last_sec=0;          
      }
      if(num_olds_for_deletion>0){
          rvalue=emit_old_and_delete(2,in_packet->pcap_hdr->ts.tv_sec);
          num_olds_for_deletion-=2;
          num_olds_for_deletion=num_olds_for_deletion*rvalue/2;
        
      }
  }
  else{
      //it is a offline read not based on time but on packet count!!
      //cout << "offline"<<endl;
  }

  return 0;
 

}
////////////
int Bidir_Flow_Maker_Block::set_output_point(Processing_Block *out_block){

  if (false==initialized){
     return -1;
  }
  next_stage[0]=out_block;
  if (valid_outputs<1){
     valid_outputs=1;
  };
  return 0;
};

///////////////////////
/*Takes 4 inputs:
  dest: the flow that potentially needs update
  source: the flow with the current contents!!!
  current? have no idea
  sec. the end time of the current packet/flow
*/

inline int Bidir_Flow_Maker_Block::emit_old_or_update(Tagged_IPV4_Flow *dest, 
                                                Tagged_IPV4_Flow *source,                                            
                                                Active_flow_indexer *current,
                                                unsigned int sec){
  
  //check for old
  //if ( (dest->stats.end_time() + active_flow_sec_limit  < sec) &&
  if ( (dest->stats.end_time() + flow_sec_limit[(unsigned int) dest->annot[FLOW_ANNOT_CLASS_ID].as_int32 ]  < sec) &&
       (dest->stats.end_time() !=0) ){
             //needs deletion
             //for now: print, and reset values.
             cout << "emit ";
             //cout <<dest->stats.end_time() <<" ";
             //cout << flow_sec_limit[(unsigned int) dest->annot[FLOW_ANNOT_CLASS_ID] ] << " ";
             //cout << sec << " ";
             Flow_helpers::print_flow(dest);
             flow_receiver->entry_point(dest);
             current->flow_from_index(dest); //this clears up all the stats and annots

             //update dest start time? (ciecco, aug 27,2007)
             // there is an unexpected condition... the flow has not yet been erased, but a new flo
             // is detected on the reverse direction (with matching 5tuple)... 
             // it keeps the same direction as the old flow but does not update the src_start_sec..
             dest->stats.src.start_time=sec; 
          }
  Flow_helpers::flow_stats_update(&(dest->stats.src),&(source->stats.src));
  Flow_helpers::flow_stats_update(&(dest->stats.dst),&(source->stats.dst)); 

  //finally setup the correct 

  return 0;
}

//////////
int Bidir_Flow_Maker_Block::print_db(){
   list<Tagged_IPV4_Flow>::iterator pos;
   int i;
   //cout << "final db values" <<endl;
   for(i=0;i<BIDIR_FLOW_NUM_QUEUES;i++){
      pos=data_rep[i].begin();
      while(data_rep[i].end()!=pos){
         Flow_helpers::print_flow(&(*pos));
         pos++;
      }
   }
   return 0;
}

int Bidir_Flow_Maker_Block::print_index(){
   map<Active_flow_indexer,list<Tagged_IPV4_Flow>::iterator>::iterator position;
   Active_flow_indexer in1;

   position=index.begin();
   while(index.end()!=position){
      //(position->first).print();
      in1=position->first;
      in1.print();
      cout <<  "| ";
      Flow_helpers::print_flow(&(*position->second));
      position++;
   }
   return 0; 
}




////////////////////////////////////////////////////////////

int Bidir_Flow_Maker_Block::DB_updater(Tagged_IP_Packet *in_packet){
 //convert packet into flow,
   //search for flow
   // if found update
   // if not add (flow and indexes..)

   map<Active_flow_indexer,list<Tagged_IPV4_Flow>::iterator>::iterator position;
   Tagged_IPV4_Flow forward,reverse, side_effected;
   Tagged_IPV4_Flow *flow_source;
   list<Tagged_IPV4_Flow>::iterator local,local2;

   int rvalue;
   Active_flow_indexer current;
   int dest_queue,current_queue;
   uint8_t packet_is_flow_reverse=1;

   rvalue=Flow_helpers::packet_to_ipv4_flows(in_packet,&forward,&reverse,&side_effected,true);

   if(rvalue<0){
      return rvalue;
   }

   switch(rvalue){
         case 0:
          /*if (reverse.src_port==51213 || reverse.dst_port==51213){
               cout << "here!" ;
               Flow_helpers::print_flow(&reverse);
               print_db();
               cout << "index" <<endl;
               print_index();
          }*/

          // find reverse, 
          // if found update
          // else find forward 
          //      if found update
          //         else insert forward flow, insert index values
          
          // find reverse
          // if found update
          // else if protocols differ
          //           find reverse-of-reverse
          

          current.create_from_flow(&reverse);
          position=index.find(current);
          if((index.end()!=position) ){//&& (current.equal_to_flow(&(*(position->second))  ) )){//found reverse
               flow_source=&reverse;
          }
          else{//did not find reverse
             packet_is_flow_reverse=0;
             flow_source=&forward;
             current.create_from_flow(&forward);
             position=index.find(current); 
             if (index.end()==position && (forward.protocol!=reverse.protocol)){
                  //find make reverse of reverse
                  Flow_helpers::make_reverse(&reverse,&side_effected);
                  current.create_from_flow(&side_effected);
                  position=index.find(current);
                  if(index.end()!=position){//found
                     flow_source=&side_effected;
                     }
                  else{//reset vals
                       current.create_from_flow(&forward);
                     }
                 }
             

             // //next line revisited on sept 16.. removed or...
             if((index.end()==position) ){ // || !(current.equal_to_flow(&(*(position->second))  ))  ){
                
                //need to add one, in the fast position one
                current.flow_from_index(&side_effected);
                data_rep[0].push_front(side_effected);
                index[current]=data_rep[0].begin();
                //find new position and verify
                position=index.find(current);

                //cout << "inserting new!";
                //current.print();
                //cout <<endl;
                inserted_in_last_sec++;

                                          //next line revisited on sept 16,2006 removed or
                if(index.end()==position){ //|| !(current.equal_to_flow(&(*(position->second))  ))  ) {
                    cout <<"inserted not found!!";
                    Flow_helpers::print_flow(&side_effected);
                    exit(1);
                }
             }
          }
          //check if it is old, if it is emit/delete and insert new data, otherwise, update.
          //position is a pair, whose second value is what we are interested in!

          //if (reverse.src_port==51213 || reverse.dst_port==51213){
          //     cout << "new_index" <<endl;
          //     print_index();
          //} 
 
          //Flow_helpers::print_flow(&(*(position->second)));     
          emit_old_or_update(&(*(position->second)),flow_source,&current,in_packet->pcap_hdr->ts.tv_sec);

          //annotate packet dir in flow (aug 31, 2007)
          position->second->annot[FLOW_ANNOT_PACK_DIR_HIST].as_int32=
                position->second->annot[FLOW_ANNOT_PACK_DIR_HIST].as_int32<<1 |packet_is_flow_reverse ;

          //annoate packet with its current flow!
          in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr=(void *) (&(*(position->second)));
          //annotate packet with ist current direction 
          in_packet->annot[PACKET_ANNOT_PACK_DIR].as_int32=packet_is_flow_reverse;

          // do splicing...
          local=position->second;  
          local2=local;
          local2++;  
          //if(local!=data_rep.begin()){
          //   data_rep.splice(data_rep.begin(),data_rep,local,local2);
          //}
          dest_queue=get_flow_class(&(*(position->second)));
          current_queue=(unsigned int) position->second->annot[FLOW_ANNOT_CLASS_ID].as_int32;
          if(local!=data_rep[dest_queue].begin()){
             data_rep[dest_queue].splice(data_rep[dest_queue].begin(),data_rep[current_queue],local,local2);
             position->second->annot[FLOW_ANNOT_CLASS_ID].as_ptr=(void *)dest_queue; 
          };

          break;
         case 1:  // icmp related where hosts  do not match!
          //find forward.. if found update if not found insert
          //find reverse if found update, if not found ignore!!!

          //find forward
          current.create_from_flow(&forward);
          position=index.find(current);
          flow_source=&forward;
          if(index.end()==position){//forward not found, inserting!
                current.flow_from_index(&side_effected);
                data_rep[0].push_front(side_effected);
                index[current]=data_rep[0].begin();
                position=index.find(current);
                if(index.end()==position){
                    cout <<"inserted not found!!";
                    Flow_helpers::print_flow(&side_effected);
                    exit(1);
                }
                inserted_in_last_sec++;
          }
          //call update 
          emit_old_or_update(&(*(position->second)),flow_source,&current,in_packet->pcap_hdr->ts.tv_sec);
          in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr=(void *) (&(*(position->second)));

          //now reverse
          current.create_from_flow(&reverse);
          position=index.find(current);
          if(index.end()!=position){//found reverse
               flow_source=&reverse;
               emit_old_or_update(&(*(position->second)),flow_source,&current,in_packet->pcap_hdr->ts.tv_sec);
               in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr=(void *) (&(*(position->second)));
          }


          break;
         default:
            in_packet->annot[PACKET_ANNOT_BIDIR_FLOW].as_ptr=NULL;
            return -1;

   }
   return rvalue;
}

///////////////////////////////
int  Bidir_Flow_Maker_Block::set_flow_output_point(Processing_Block *out_block){
   flow_receiver=out_block;
   return 0;
}

////////////
int Bidir_Flow_Maker_Block::emit_all_flows(){
   list<Tagged_IPV4_Flow>::iterator pos;
   int i;
   //db insert
   for(i=0;i<BIDIR_FLOW_NUM_QUEUES;i++){
      pos=data_rep[i].begin();
      while(data_rep[i].end()!=pos){
         flow_receiver->entry_point(&(*pos));
         pos++;
      }
   }
   return 0;
};

//////
int Bidir_Flow_Maker_Block::emit_old_and_delete(int up_to_n,unsigned int current_sec){
   //on error this function MUST exit
   int i=0;
   int j=0;
   list<Tagged_IPV4_Flow>::iterator pos;
   Active_flow_indexer current;
   map<Active_flow_indexer,list<Tagged_IPV4_Flow>::iterator>::iterator index_position;
   int deleted=0;

   for(j=0;j<BIDIR_FLOW_NUM_QUEUES;j++){
      i=0;
      while(data_rep[j].begin()!=data_rep[j].end() && i<up_to_n ){
         //dec data_rep end.. this marks the oldest flow
         pos=data_rep[j].end();
         pos--;
         if(pos->stats.end_time()+flow_sec_limit[j]<current_sec){
            //emit and delete
            flow_receiver->entry_point(&(*pos));
            //delete from both data repository AND from index required... 
            current.create_from_flow(&(*pos));
            index_position=index.find(current);
            if((index.end()==index_position) ){
                  perror("wtf? index not found!!!");
                  Flow_helpers::print_flow(&(*pos)); 
                  print_index();
                  print_db();  
                  exit(1);             
            }
            else{
                 index.erase(index_position);
                 //cout << "index found...\n";
            } 
            data_rep[j].erase(pos);
            deleted++;
         }
         i++;
      }
   }
   //cout<< " index size="<<index.size() ;//<< "data_rep.size= "<<data_rep.size()<<endl;
   //cout << " data_repi[0].size= "<<data_rep[0].size()<<"data_repi[1].size= "<<data_rep[1].size()<<endl;
   last_old_check=current_sec;
   return deleted;
}

inline int Bidir_Flow_Maker_Block::get_flow_class(Tagged_IPV4_Flow *inflow){
  //calculate the flow class
  int test;
  int flags;
  flags=inflow->stats.tcp_flags();
  test=flags & 0x05;
  if((6==inflow->protocol) && 
     (0 == (inflow->stats.tcp_flags() & 0x05)) && 
     (0x10== (inflow->stats.dst.tcp_flags & 0x10)) ){ //if tcp and no rst or fin flgs seen and
                                                     // ack on dst
    return 1;
  }

  //default
  return 0;
}


#endif
