#!/usr/bin/perl
# 
# Cumulus Firewall 
# Copyright (C) 2000  Øyvind Jelstad, Cumulus IT AS
# 
# $Id: index.cgi,v 1.6 2003/09/23 13:29:23 oyvind Exp $
#

require "fwrap-lib.pl";
#require '../cfw/obj-lib.pl';

require "squid-lib.pl";

if ($in{'log'}) {
 
 redirect("view_log.cgi");
}

if (! $access{'lrules'}) { &error($text{'acl_lrules'} . ": ".$text{'no'} ) }


&header("Blocklist", undef, "blocklist", 1, 1, undef,
        $text{'author'} ." <BR>" . $text{'homepage'});

#&toolbar;

@ps=&parse_script();


# print @ps;

    $objects = &get_objects;
    $services = &get_objects( "servicefile" );		

if ($in{'rule'}) {
   print "Rule nr $in{'rule'} ";
}


print "<BR><HR>";

print "<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb WIDTH=100%>\n<TR>",
#      "<TD COLSPAN=9 $tb WIDTH=100%><B>$text{'erule_title'}</B></TD></TR>",
"\n";

print "<TR $tb><TD><B>Nr.</B></TD>";
print "<TD><B>Av/P&aring;</B></TD>";
print "<TD><B>$text{'erule_source'}</B></TD>";
print "<TD><B>$text{'erule_dest'}</B></TD>";

print "<TD><B>Service</B></TD>";

#print "<TH><B>$text{'erule_frag'}</B></TD>";
print "<TH><B>$text{'erule_log'}</B></TD>";
#print "<TD><B>$text{'erule_tos'}</B></TD>";

print "<TD><B>$text{'erule_action'}</B></TD>";
#print "<TD><B>Status</B></TD>";
print "<TD><B>$text{'erule_comment'}</B></TD></TR>\n";


foreach $l (@ps) {

  $line=$l->{'nr'};

 $source=$l->{'source'};
 $source || ($source = "&nbsp;");

 $dest=$l->{'dest'};
 $dest || ($dest = "&nbsp;");

 $proto=($l->{'proto'}) ?  $l->{'proto'} : "Any";
  $action=($l->{'action'}) ?  $l->{'action'} : "Drop";

 $frag=($l->{'frag'}) ?  "X" : "&nbsp;";

 $log=($l->{'log'}) ? "X" : "&nbsp;";

 $tos=($l->{'tos'}) ? "$tos{$l->{'tos'}}" : "&nbsp;";

 $disable=$l->{'disable'};

 $comment=$l->{'comment'};
 $comment || ($comment = "&nbsp;");

   if ( $l->{'disable'} ) {
     $bgc = "<TR bgcolor=#c0c0FF >";
     $button="images/b-green.gif";
     $aksjon = "Enable rule!";
     $status = "NONE";
   }else{
     $bgc = "<TR bgcolor=#F07070 >";
     $button="images/b-red.gif";
     $aksjon = "Disable!"; 
#     $status = "BLOCK";
     $status = $action;
     
   }

if ( $action eq "DENY" || $action eq "REJECT") {

   print $bgc;
   print "<TD><A HREF=\"block_save.cgi?rule=$line\">$line</A></TD>";
   print "<TD><A HREF=\"block_save.cgi?rule=$line\"><IMG SRC = \"" . $button . "\"
          BORDER=\"0\" ALT=\"" . $aksjon . "\"></A>";
		      
} else {
   next if $config{'hide'};
   if ( ! $l->{'disable'} ) { $status = "RETURN";}
   print "<TR bgcolor=#F0F070 >";
   $button="images/b-green.gif";
   print "<TD><A HREF=\"block_save.cgi?rule=$line\">$line</A></TD>";
   print "<TD><A HREF=\"block_save.cgi?rule=$line\"><IMG SRC = \"" . $button . "\"
          BORDER=\"0\" ALT=\"" . $aksjon . "\"></A>";

}
$v = $objects->{$source};
if (! $v ) {
   print "<TD >$source</TD>";
} else {
    $type=$v->type;
    print "<TD><A HREF=\" object_viewer.cgi?object=$source\"> $source </A> </TD>";
}


$v = $objects->{$dest};
if (! $v ) {
   print "<TD >$dest</TD>";
} else {
    $type=$v->type;
     print "<TD><A HREF=\" object_viewer.cgi?object=$dest\"> $dest </A> </TD>";
}

$v = $services->{$proto};
if (! $v ) {
   print "<TD >$proto</TD>";
} else {
    $type=$v->type;
    print "<TD><A HREF=\" object_viewer.cgi?service=1&object=$proto\"> $proto </A> </TD>";
}


# print "<TD ALIGN=center><B>$frag</B></TD>";
 print "<TD ALIGN=center><B>$log</B></TD>";
# print "<TD >$tos</TD>";

# print "<TD >$action</TD>";
 print "<TD >$status</TD>";
 print "<TD >$comment</TD>";
 print "</TR>\n";
}


print "</TABLE>\n";

#print "<BR><BR>\n";
#print "<A HREF=\"edit_rule.cgi?chain=$in{'chain'}\">$text{'erule_crule'}</A>\n";
print "\n";


#------------------------------Squid acl-----------------------------------

@acl = &parse_acl_file;

print "<h2>Squid ACL</h2>";

print "<TABLE BORDER=2 CELLPADDING=2 CELLSPACING=0 $cb WIDTH=100%>\n<TR>",
#      "<TD COLSPAN=9 $tb WIDTH=100%><B>$text{'erule_title'}</B></TD></TR>",
"\n";

print "<TR $tb><TD><B>Nr.</B></TD>";
print "<TD><B>Av/P&aring;</B></TD>";
print "<TD><B>$text{'eacl_action'}</B></TD>";
print "<TD><B>$text{'eacl_value'}</B></TD></TR>\n";


foreach $l (@acl) {

  $line=$l->{'nr'};
  $action=($l->{'action'}) ?  $l->{'action'} : "Deny";
  $comment=($l->{'values'}) ?  $l->{'values'} : "";

   if ( $action eq "allow" ) {
     $bgc = "<TR bgcolor=#c0ffc0 >";
     $button="images/b-green.gif";
     $aksjon = "Enable rule!";
     $status = "NONE";
   }else{
     $bgc = "<TR bgcolor=#F07070 >";
     $button="images/b-red.gif";
     $aksjon = "Disable!"; 
#     $status = "BLOCK";
     $status = $action;
     
   }

# if ( $action eq "DENY" || $action eq "REJECT") {

   print $bgc;
   print "<TD><A HREF=\"acl_save.cgi?rule=$line\">$line</A></TD>";
   print "<TD><A HREF=\"acl_save.cgi?rule=$line\"><IMG SRC = \"" . $button . "\"
          BORDER=\"0\" ALT=\"" . $aksjon . "\"></A>";
		      
# } else {
#    next if $config{'hide'};
#   if ( ! $l->{'disable'} ) { $status = "RETURN";}
#   print "<TR bgcolor=#F0F070 >";
##   $button="images/b-green.gif";
#   print "<TD><A HREF=\"block_save.cgi?rule=$line\">$line</A></TD>";
#   print "<TD><A HREF=\"block_save.cgi?rule=$line\"><IMG SRC = \"" . $button . "\"
#          BORDER=\"0\" ALT=\"" . $aksjon . "\"></A>";

# }

print "<TD >$action</TD>";
# print "<TD >$status</TD>";
print "<TD >$comment</TD>";
# print "<TD >$l->{'line'}</TD>";
 print "</TR>\n";
}


print "</TABLE>\n";

#print "<BR><BR>\n";
#print "<A HREF=\"edit_rule.cgi?chain=$in{'chain'}\">$text{'erule_crule'}</A>\n";
print "\n";


#--------------------------------------------------------------------------
if ($in{'generate'}) {
require "./block-lib.pl";
   if (! $access{'exscript'}) { &error($text{'acl_exscript'} . ": ".$text{'no'} ) }
   &generate_fw_script;
#  &safe_exec("Restart FW",$config{'scriptfile'});
      
      print $msg;
}
if ($in{'view'}) {
#print "scriptfile = ". $config{'scriptfile'};
   if (! $access{'vscript'}) { &error($text{'acl_vscript'} . ": ".$text{'no'} ) }
   open(FILE, "$config{'scriptfile'}") || &error($text{'sman_err_read'});	
   print "<HR><pre>\n"; 
    while (<FILE>) {
      print;
    } 
   print $msg;
}

if ($in{'install'}) {
   if (! $access{'exscript'}) { &error($text{'acl_exscript'} . ": ".$text{'no'} ) }
   require "./block-lib.pl";
   $msg = "";
   print "<h3>Genererer blokkeringsscript...</h3>\n";
   &generate_fw_script;
   print $msg;
   $msg = "";
   if (!-x $config{'scriptfile'}) {
    chmod 0755, $config{'scriptfile'};
    $msg="$text{'sman_msg_exec'}<BR>";
   }
      
  &safe_exec("Installerer BLOCKLIST",$config{'scriptfile'});
      
      print $msg;
}

if ($in{'chain'}) {
   if (! $access{'vlog'}) { &error($text{'acl_vlog'} . ": ".$text{'no'} ) }
   &safe_exec("BLOCK chain","$IPTABLES -L BLOCK -n -v");
}


############  Buttons #######################
print "<center>\n";

print "<FORM ACTION=\"index.cgi\" METHOD=post>";


print "<INPUT TYPE=submit NAME=\"generate\" VALUE=\"Generer script\">\n";
print "<INPUT TYPE=submit NAME=\"view\" VALUE=\"Se på script\">\n";
print "<INPUT TYPE=submit NAME=\"install\" VALUE=\"Installer script\">\n";
print "<INPUT TYPE=submit NAME=\"chain\" VALUE=\"Se på filter\">\n";
print "<INPUT TYPE=submit NAME=\"log\" VALUE=\"Log\">\n";

print "</FORM><BR><HR>\n";

print "\n</center>";


&footer("", $text{'erule_return'});



### END of edit_chain.cgi ###.
