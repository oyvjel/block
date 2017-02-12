#!/usr/bin/perl
# 
# Cumulus Firewall 
# Copyright (C) 2000  Øyvind Jelstad, Cumulus IT AS
# 
# $Id: onoff.pl,v 1.2 2005/03/22 11:22:30 oyvind Exp $
#
# This script is to be called from command line, shell script or from cron.
# It must be called with full pathname, as the path determins the module to operate on.
# Syntax:
# <path to module>/onoff.pl <rule> [on]
# If the 2.nd parameter is absent the rule is turned off.
#
# Cron example: ( /etc/cron.d/blocklist )
#
# */2 * * * * root /usr/share/webmin/block/onoff.pl 3 on   >/dev/null 2>&1
# 1-59/2 * * * * root /usr/share/webmin/block/onoff.pl 3   >/dev/null 2>&1
  

#
$ENV{'WEBMIN_CONFIG'} = "/etc/webmin";

$ENV{'WEBMIN_VAR'} = "/var/webmin";
$ENV{'SCRIPT_FILENAME'} = $0;

$sn= $0;
if ( $sn =~ /(.*?)([^\/]+)$/ ) {
    print "script: $2, path $1 \n";
    $path=$1;
    chdir $path or die "Can't cd to $path: $!\n"    
}

$main::no_acl_check++;

print "$0 .... endrer regel $ARGV[0] \n";


require "fwrap-lib.pl";

$regel=$ARGV[0];


$lines=&read_file_lines($config{'rulefile'});
      $l=&parse_line($lines->[$regel],$regel);

if ( $l->{'action'} ne "DENY" && $l->{'action'} ne "REJECT" ) {
  &error("Du har ikke adgang til å endre denne regelen");
}  

#     $disable = $l->{'disable'} ? 0:1;    
     $disable = $ARGV[1] ? 0:1;    
$newline=
#    $in{'nr'}
    "$l->{'source'}"
    .",$l->{'dest'}"
    .",$l->{'proto'}"
    .",$l->{'frag'}"
    .",$l->{'log'}"
    .",$l->{'tos'}"
    .",$l->{'action'}"
    .",". $disable    
    .",$l->{'comment'}";
   

      $lines->[$regel]=$newline;

&flush_file_lines();

   if (! $access{'exscript'}) { &error($text{'acl_exscript'} . ": ".$text{'no'} ) }
   require "./block-lib.pl";
   $msg = "";
#    print "<h3>Genererer blokkeringsscript...</h3>\n";
   &generate_fw_script;
   print $msg;
   $msg = "";
   if (!-x $config{'scriptfile'}) {
    chmod 0755, $config{'scriptfile'};
#    $msg="$text{'sman_msg_exec'}<BR>";
   }
      
  &safe_exec("Installerer BLOCKLIST",$config{'scriptfile'});
      
#     print $msg;


### END ###.
