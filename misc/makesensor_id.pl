#!/usr/bin/perl
# Copyright (C) 2005 The Trustees of Indiana University.  All rights reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#


#
#----- make sensor_id

use strict;
use Getopt::Std;
use IO::Socket;

#this hash does not have to have cryptogtaphic properties!!
# but these are not needed in this case 
sub do_hash{
  my $invalue =shift;

  my $mult=241;  #both primes.. I think it matters, rechecked the
                 #multiplaction does not need to be prime
  my $div=251;
 
  #this is nothing by a linear hash... 
  return ($invalue*$mult)%$div;   
}

sub main{
  my %opt;
  my $manager_ip;
 
  my $hash_val;
  my $sensor_id;
  my $print_val;
  my $days_since_epoch;
  my $fh;

  getopts("i:",\%opt);

  if($opt{i}){
    $manager_ip=unpack('N',inet_aton($opt{i}));
  }
  else
  {
    die "cannot run without managers ip.. aborting";
  }
  open($fh,"+>/hw/conf/HwSENSOR_ID") or die "cannot create sensor_id file";
  

  $hash_val=(do_hash($manager_ip))%256;
  $days_since_epoch=(int(time()/(3600*24)))%32768;

  $sensor_id=$days_since_epoch*65536+$hash_val*256+int(rand 256);  

  #$print_val= "sensor=".$sensor_id."  sens=".inet_ntoa(pack('N',$sensor_id));
  #$print_val .=" days=$days_since_epoch \n";
  #print(" hello '$print_val'");
  #print ("hello");
  $print_val=inet_ntoa(pack('N',$sensor_id));
  print $fh $print_val or die "cannot write to file";

}

main();


