#!/usr/bin/perl
# 
# Cumulus Firewall 
# Copyright (C) 2000  Øyvind Jelstad, Cumulus IT AS
# 
# $Id: acl_save.cgi,v 1.2 2005/03/22 11:22:30 oyvind Exp $

require "fwrap-lib.pl";

require "squid-lib.pl";


if (! $access{'erules'}) { &error($text{'acl_erules'} . ": ".$text{'no'} ) }



$lines=&read_file_lines($config{'aclfile'});
#if (!$$lines[$in{'rule'}]) { &error("No such rule found") }

      $l=&parse_acl($lines->[$in{'rule'}],$in{'rule'});

# if ( $l->{'action'} ne "DENY" && $l->{'action'} ne "REJECT" ) {
#   &error("Du har ikke adgang til å endre denne regelen");
# }  

#     $disable = $l->{'disable'} ? 0:1;    

$action = $l->{'action'} eq "deny" ? "allow" : "deny";
$newline=
#    $in{'nr'}
    "$l->{'name'} "
    . $action
    ." $l->{'values'}";

   

      $lines->[$in{'rule'}]=$newline;


# for (my $n=0; $n<@{$lines}; $n++) {
#    $tmpstr= $sq->[$n];
#    print $tmpstr ."   \n";
# }

&flush_file_lines();

$sq=&read_file_lines($config{'squidconf'});
# &header("Blocklist", undef, "blocklist", 1, 1, undef,
#        $text{'author'} ." <BR>" . $text{'homepage'});

# print "<pre>\n";
# print @{$sq};

  $istart = &indexof("### CFW ACL START: DO NOT EDIT THIS LINE ###",@{$sq});
#      print "Start = $istart \n";
   if ($istart < 0) {     
# Finn 1. acl. 
    for (my $n=0; $n<@{$sq}; $n++) {
     $tmpstr= $sq->[$n];
	if ($tmpstr =~ /^\s*http_access / ){
#	    print $tmpstr ."   \n";
	    $istart = $n;
	    splice ( @{$sq},$istart,0,"### CFW ACL START: DO NOT EDIT THIS LINE ###"); 
	    last ;
	}
    }
  }
  $istart++;
  $istop = &indexof("### CFW ACL END: DO NOT EDIT THIS LINE ###",@{$sq});
  if ($istop < 0) {     
      $istop = $istart;
      splice ( @{$sq},$istart,0,"### CFW ACL END: DO NOT EDIT THIS LINE ###"); 

  }

#      print "Start = $istart \n";
#      print "Stop = $istop \n";


splice ( @{$sq},$istart,$istop-$istart,@{$lines}); 

#    for (my $n=0; $n<@{$sq}; $n++) {
#     $tmpstr= $sq->[$n];
#    print $tmpstr ."   \n";
#    }
# print "</pre>\n";

&flush_file_lines();

system ( " /etc/init.d/squid reload ");
redirect("index.cgi?install=0");

### END of save_rule.cgi ###.
