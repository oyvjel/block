#!/usr/bin/perl
# 
# Cumulus Firewall 
# Copyright (C) 2000  Øyvind Jelstad, Cumulus IT AS
# 
# $Id: view_log.cgi,v 1.3 2002/12/11 01:24:03 oyvind Exp $
#

require "fwrap-lib.pl";

if (! $access{'vlog'}) { &error($text{'acl_vlog'} . ": ".$text{'no'} ) }
   
$Color{'ACCEPT'}="#00aa00";
$Color{'DENY'}="#FF0000";
$Color{'DROP'}="#FF0000";
$Color{'MASQ'}="#0000FF";

   &header($text{'log'}, undef, "intro", 1, 1, undef,
        $text{'author'} ." <BR>" . $text{'homepage'});

#   print "<HR><pre>\n"; 
#   print  keys %in;
#   print "<HR></pre>\n"; 

$logfile  = ($config{'logfile'}) ? $config{'logfile'} : "/var/log/messages";
# print "Logfile = $logfile ";

if ( $in{'command'} eq "Follow" ) { 
print <<EOM;
<HEAD>
<TITLE>Firewall Log</TITLE>
<META HTTP-EQUIV="refresh"
   CONTENT="15">
   </HEAD>
   <BODY>
EOM


   open(FILE, "tail -20 $logfile |") || &error($text{'sman_err_read'});	

}else{
#   open(FILE, "/var/log/kern.log") || &error($text{'sman_err_read'});	
      open(FILE, "tail -200 $logfile |") || &error($text{'sman_err_read'});	
}   
#   print "<HR><pre>\n"; 
   print "<TABLE border=0>\n";
   print "<TR $tb> \n";
   print "<TD>Time</TD>";
   print "<TD>FW</TD>";
   print "<TD>Filter</TD>";
   print "<TD>Rule</TD>";
   print "<TD>Action</TD>";
   print "<TD>Interf.</TD>";
   print "<TD>Proto</TD>";
   print "<TD>Source</TD>";
   print "<TD>S.Port</TD>";
   print "<TD>Dest</TD>";
   print "<TD>D.port</TD>";
   print "<TD>Syn</TD>";
   print "</TR>\n";


$mtime = $in{'time'} ?  $in{'time'} : ".*";
$mFW = $in{'FW'} ?  $in{'FW'} : ".*";
$mfilter = $in{'filter'} ?  $in{'filter'} : "\\S*";
$maction = $in{'action'} ?  $in{'action'} : "\\S*";
$minterf = $in{'interf'} ?  $in{'interf'} : "\\S*";
$mproto = $in{'proto'} ?  $in{'proto'} : "\\S*";
$msource = $in{'source'} ?  $in{'source'} : ".*";
$msport = $in{'sport'} ?  $in{'sport'} : ".*";
$mdest = $in{'dest'} ?  $in{'dest'} : "\\S*";
$mdport = $in{'dport'} ?  $in{'dport'} : "\\S*";
$mflag = $in{'flag'} ?  $in{'flag'} : "\\S*";
$mrule = $in{'rule'} ?  $in{'rule'} : "\\S*";


    while (<FILE>) {
#      print;

	    
#       next if $lline ++ < $fpos;

	if ( m/^($mtime) ($mFW) kernel: cfw:($mfilter):($maction) RULE=($mrule) IN=($minterf) OUT=(\S*) .*?SRC=($msource) DST=($mdest) .*?(PROTO=.*)/){ 
#	   :($mdport) L=(.*) S=(.*) I=(.*) F=(.*) T=(\d*) ([SYN]*) ?\(\#($mrule)\) PROTO=($mproto)/ ) {
          ($tid,$fw,$filter,$aksjon,$rule,$IF,$OIF,$fra,$til,$rest) = ($1, $2, $3, $4,$5, $6, $7, $8,$9, $10 );
 
	   
	   
	    ($prot,$fraport,$tilport,$syn) = ("", "", "","" );
	   
	   
	  if ( $rest =~ /.*?PROTO=($mproto) SPT=($msport) DPT=($mdport) .*?([SYN]*?) /) {
	      ($prot,$fraport,$tilport,$syn) = ($1, $2, $3, $4 );
	  }
	  elsif ( $rest =~ /.*PROTO=($mproto) TYPE=(.*?) CODE=(.*?) /) {
	      ($prot,$fraport,$tilport) = ($1, "type ".$2, "code ". $3 );
	  }
	  elsif ( $rest =~ /.*PROTO=($mproto) /) {
	      ($prot) = ($1);
	  }else{
#	      next;
	  }
	   
          $fg = "<font COLOR=$Color{$aksjon}>";
	  $log .= "<TR>  \n"
	       . "<TD>$fg $tid</TD>"
	       . "<TD>$fg $fw</TD>"
	       . "<TD>$fg $filter</TD>"
	       . "<TD>$fg $rule</TD>"
	       ."<TD>$fg $aksjon</TD>"
	       . "<TD>$fg $IF</TD>"
	       . "<TD>$fg $prot</TD>"
	       . "<TD>$fg $fra</TD>"
	       . "<TD>$fg $fraport</TD>"
	       . "<TD>$fg $til</TD>"
	       . "<TD>$fg $tilport</TD>"
	       . "<TD>$fg $syn</TD>"
	       . "<TD>$fg $lline</TD>"
	       . "</TR>\n";
  
#         last if $cur++ > $lines;
						       
        }						       
	
       if ( m/^($mtime) ($mFW) cfw: ($mfilter): ($maction): (.*)$/ ) {
          ($tid,$fw,$filter,$aksjon,$melding) = ($1, $2, $3, $4, $5 );
	  
          $fg = "<font COLOR=$Color{$aksjon}>";
	  $log .= "<TR>  \n"
	       . "<TD>$fg $tid</TD>"
	       . "<TD>$fg $fw</TD>"
	       . "<TD>$fg $filter</TD>"
	       . "<TD>$fg </TD>"
	       ."<TD>$fg $aksjon</TD>"
	       . "<TD colspan=7>$fg $melding</TD>"
	       . "</TR>\n";
  
#         last if $cur++ > $lines;
						       
        }						       




    }
    print $log;
    
#   print "</pre><HR>\n";
   print "</TABLE>\n";

&footer("./", $text{'return_to_top'});
   exit;

