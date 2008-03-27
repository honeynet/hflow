#!/usr/bin/perl
# (C) 2005 The Trustees of Indiana University.  All rights reserved.
#
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
#----- sid_map_upload:  uploads IDS signature to id mapping
#-----
#----- Version:  $Id: sid_map_upload.pl 1757 2005-07-15 16:30:26Z cvs $
#-----
#----- Authors:  Edward Balas <ebalas@iu.edu>

use strict;
use 5.004;
use Getopt::Std;
use Time::gmtime;
use DBI;
use DBD::mysql;
use POSIX;
use FileHandle;
use Socket;
use English;


my $dbh;
my $database    = "hflow";
my $dbpasswd    = "";
my $dbuid       = "hflowdaemon";
my $dbserver    = "";
my $dbport      = "";
my $sensor_id   = "0";


sub main{ 

    my $infile;
    
    #------- get user input
    my %opt;
    
    
    getopts("r:u:p:d:s:i:h",\%opt);
    
    if($opt{r}){
        $infile = $opt{r};
    }

    if($opt{u}){
        $dbuid = $opt{u};
    }

    if($opt{p}){
        $dbpasswd = $opt{p};
    }

    if($opt{d}){
        $database = $opt{d};
    }

    if($opt{s}){
        $dbserver = $opt{s};
    }

    if($opt{i}){
        $sensor_id = unpack('N',inet_aton($opt{i}));
    } 


    if($opt{h}){
        print "$0:(Loads SID to Sig mappings into specified database)\n";
	print "\t-r  map file to process\n";
        print "\t-u  User ID\n";
        print "\t-p  Passwd\n";
        print "\t-d  Database Name\n";
        print "\t-s  Server Name or IP\n";
        print "\t-P  Port Number\n";
	print "\t-i  Sensor ID\n";
        print "\t-h  Help\n";
        exit;

    }
    
    #------- have p0f process the specfied file
    if(!defined $infile){
	die " -r file.map is a required arguement\n";
    }
    $dbh = DBI->connect("DBI:mysql:database=$database;host=$dbserver;port=$dbport",$dbuid,$dbpasswd);

    open(MAP,"$infile ") || die "unable to open $infile\n";


    my $sid;
    my $msg;
    my $ref;
   
    my $query = "insert into ids_sig (sensor_id,ids_sig_id, sig_name, reference,ids_sig_gen) values (?,?,?,?,1) ";

    my $sql = $dbh->prepare($query);
 
    while (<MAP>){
	next if(/^#/);
	chomp;

	($sid,$msg,$ref) = split(/ \|\| /,$_,3);	

	$sql->execute($sensor_id,$sid,$msg,$ref);
    }
};


main();
