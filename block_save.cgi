#!/usr/bin/perl
# 
# Cumulus Firewall 
# Copyright (C) 2000  Øyvind Jelstad, Cumulus IT AS
# 
# $Id: block_save.cgi,v 1.4 2005/03/22 11:22:30 oyvind Exp $

require "fwrap-lib.pl";

if (! $access{'erules'}) { &error($text{'acl_erules'} . ": ".$text{'no'} ) }


#if ($in{'chain'} eq "") { &error($text{'srule_err_nochain'}) }
if ((&indexof($in{'sport'}, &get_services_list()) >= 0) && $in{'proto'} !~ /^(tcp|udp)$/i) {
 &error($text{'srule_err_servport'});
}
if ((&indexof($in{'dport'}, &get_services_list()) >= 0) && $in{'proto'} !~ /^(tcp|udp)$/i) {
 &error($text{'srule_err_servport'});
}

$lines=&read_file_lines($config{'rulefile'});
#if (!$$lines[$in{'rule'}]) { &error("No such rule found") }

      $l=&parse_line($lines->[$in{'rule'}],$in{'rule'});

if ( $l->{'action'} ne "DENY" && $l->{'action'} ne "REJECT" ) {
  &error("Du har ikke adgang til å endre denne regelen");
}  

     $disable = $l->{'disable'} ? 0:1;    
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
   

      $lines->[$in{'rule'}]=$newline;

&flush_file_lines();

redirect("index.cgi?install=1");

### END of save_rule.cgi ###.
