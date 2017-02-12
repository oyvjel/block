#!/usr/bin/perl
# 
# Cumulus Firewall 
# Copyright (C) 2000  Øyvind Jelstad, Cumulus IT AS
# 
# $Id: log_manager.cgi,v 1.2 2001/02/21 14:31:26 oyvind Exp $
#

require "fwrap-lib.pl";

#@ps=&parse_script();
#$chains=&find_arg_struct('-N', \@ps);

&header("Log", undef, "intro", 1, 1, undef,
        $text{'author'} ." <BR>" . $text{'homepage'});

&toolbar;

print <<EOM;

<TABLE BORDER=0 CELLSPACING=0 CELLPADDING=0 WIDTH=100%>

  <TD VALIGN=top ALIGN=center>

   <TABLE BORDER=2 CELLSPACING=0 CELLPADDING=2 $cb>
    <TR $tb>
     <TH>$text{'logs'}</TH>
     <TH>$text{'vpn_index'}</TH>
     <TH>$text{'filters'}</TH>
    </TR>
    <TR $cb>
      <FORM ACTION=view_log.cgi METHOD=get>
     <TD>
       <INPUT TYPE=submit VALUE="View" NAME="command">
       <INPUT TYPE=submit VALUE="Follow" NAME="command">
    </TD>
       </FORM>
    
EOM

############  Buttons #######################

print "<FORM ACTION=\"log_manager.cgi\" METHOD=post NAME=\"vpn\">";
print "<TD><INPUT TYPE=submit NAME=\"eroute\" VALUE=\"VPN eroute\">\n";
print "<INPUT TYPE=submit NAME=\"status\" VALUE=\"VPN status\">\n";
print "</td><td>";

print "<INPUT TYPE=submit NAME=\"input\" VALUE=\"Input\">\n";
print "<INPUT TYPE=submit NAME=\"forward\" VALUE=\"Forward\">\n";
print "<INPUT TYPE=submit NAME=\"output\" VALUE=\"Output\">\n";
print "<INPUT TYPE=submit NAME=\"masq\" VALUE=\"Masquerade\">\n";
print "<INPUT TYPE=submit NAME=\"reset\" VALUE=\"Reset\">\n";

print "</td></FORM>";

print <<EOM;
    </TD> 
    </TR>
   </TABLE>

  </TD>
 </TR>
</TABLE>
</TR></TABLE>

EOM


################ ACTIONS #######################


if ($in{'status'}) {
   &safe_exec("IPSEC Status","/usr/local/sbin/ipsec look");
}

if ($in{'eroute'}) {
   &safe_exec("IPSEC Eroute","/usr/local/sbin/ipsec eroute");
}

if ($in{'input'}) {
   &safe_exec("Input chain","ipchains -L input -v");
}

if ($in{'forward'}) {
   &safe_exec("Forward chain","ipchains -L forward -v");
}

if ($in{'output'}) {
   &safe_exec("Output chain","ipchains -L output -v");
}

if ($in{'masq'}) {
   &safe_exec("Masqueraded sessions","ipchains -L  -M -v");
}

if ($in{'reset'}) {
   &safe_exec("Reset counters","ipchains -L  -Z ");
}


&footer("./", $text{'return_to_top'});


### END of index.cgi ###.
