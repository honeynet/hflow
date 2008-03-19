#!/usr/bin/perl
# Copyright (C) 2007 Camilo Viecco.  All rights reserved.
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


##steps: 
# 1. make sensor id.
# 2. Create database
# 3. populate snort sigs into db
# 4. Create new sensor in db
# 5. Import old data into new db
# 6. Import sensor info into new db


use strict;
use Getopt::Std;
use IO::Socket;
use DBI;
use DBD::mysql;


my $db_root_user="roo";
my $db_root_user_pw="honey";

#--------
my $dbh;
my $database    = "hflow";
my $dbpasswd    = "";
my $dbuid       = "hflowdaemon";
my $dbserver    = "";
my $dbport      = "";
my $sensor_id   = "0";



sub do_hash{
  my $invalue =shift;

  my $mult=241;  #both primes.. I think it matters, rechecked the
                 #multiplaction does not need to be prime
  my $div=251;

  #this is nothing by a linear hash...
  return ($invalue*$mult)%$div;
}


sub force_make_sensor_id{
  my $sensor_id=shift;
  my $manage_ip;
  my $hash_val;
  my $fh;

  open(MANAGE_IP,"/hw/conf/HwMANAGE_IP") or die "cannot read managers ip";
  if(<MANAGE_IP>){
    $manage_ip=inet_ntoa(pack('N',$_));
  }
  else{
    die "Manager IP file found but content is emmpty";
  }
  open($fh,"+>/hw/conf/HwSENSOR_ID") or die "cannot create sensor_id file";  
  $hash_val=(do_hash($manage_ip))%256;
  my $days_since_epoch=(int(time()/(3600*24)))%32768;
  if (not defined $sensor_id){
    $sensor_id=$days_since_epoch*65536+$hash_val*256+int(rand 256);
  }
  print $fh $sensor_id or die "cannot write to file";  
  close($fh);
  close(MANAGE_IP);
  return $sensor_id;
}

sub cond_make_sensor_id(){
  # check if sensor id exists and is valid
  # create otherwise
  my $sensor_id;  
  my $file_sens;
  my $fh;

  open($fh,"/hw/conf/HwSENSOR_ID")
   or  $sensor_id=force_make_sensor_id(); 
  if (defined $sensor_id){
    return $sensor_id; 
  }
  if(<$fh>){
     $file_sens=unpack('N',inet_aton($_));
     $sensor_id=force_make_sensor_id($file_sens);
  }
  close($fh);
  return $sensor_id;
}

sub create_database{
   my $fh;
   open($fh,"mysql -u $db_root_user -p$db_root_user_pw < /etc/hflow/hflowd.schema |");
   while(<$fh>){
      print $_;
   }
   close($fh);
}

sub import_snort_sigs_into_db{
   my $sensor_id=shift;
   my $fh;
   open($fh,"./gen_map_upload.pl -i $sensor_id -r /etc/snort/gen-msg.map |");
   while(<$fh>){
      print $_;
   }
   close($fh);

   open($fh,"./sid_map_upload.pl -i $sensor_id -r /etc/snort/sid-msg.map |");
   while(<$fh>){
      print $_;
   }
   close($fh);

}

sub create_sensor{
   my $sensor_id=shift;
   $dbh = DBI->connect("DBI:mysql:database=$database;host=$dbserver;port=$dbport",$dbuid,$dbpasswd);
   my $query = "insert into sensor  (sensor_id,name, state,install_sec) values (?,?,'online',?) ";

   my $sql = $dbh->prepare($query);
   $sql->execute($sensor_id,"hflow2_sensor",time()) or die "cannot insert sensor";


}

sub main{
  my $sensor_id;
  $sensor_id=cond_make_sensor_id();
  create_database();
  import_snort_sigs_into_db($sensor_id);  
  create_sensor($sensor_id);
}

main();

