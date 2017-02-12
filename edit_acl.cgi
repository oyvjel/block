#!/usr/bin/perl
# edit_acl.cgi
# Display a list of all ACLs and restrictions using them

require './squid-lib.pl';
$access{'actrl'} || &error($text{'eacl_ecannot'});
&header($text{'eacl_header'}, "", "edit_acl", 0, 0, 0, &restart_button());
$conf = &get_config();

print "<hr><p>\n";
print "<table border cellpadding=5 width=100%><tr>\n";
print "<td rowspan=2 valign=top width=50%>\n";
@acl = &find_config("acl", $conf);
if (@acl) {
	# List all defined access control directives
	print "<h3>$text{'eacl_acls'}</h3>\n";
	print "<table border width=100%>\n";
	print "<tr $tb> <td><b>$text{'eacl_name'}</b></td>\n"; 
	print "<td><b>$text{'eacl_type'}</b></td>\n";
	print "<td><b>$text{'eacl_match'}</b></td> </tr>\n";
	foreach $a (@acl) {
		@v = @{$a->{'values'}};
		print "<tr $cb>\n";
		print "<td><a href=\"acl.cgi?index=$a->{'index'}\">",
		      &html_escape($v[0]),"</a></td>\n";
		print "<td nowrap>$acl_types{$v[1]}</td>\n";
		print "<td>",&html_escape(join(' ', @v[2..$#v])),"</td>\n";
		print "</tr>\n";
		}
	print "</table>\n";
	}
else {
	print "<b>$text{'eacl_noacls'}</b><br>\n";
	}
print "<form action=acl.cgi>\n";
print "<input type=submit value=\"$text{'eacl_buttcreate'}\">\n";
print "<select name=type>\n";
foreach $t (sort { $acl_types{$a} cmp $acl_types{$b} } keys %acl_types) {
	print "<option value=$t>$acl_types{$t}\n";
	}
print "</select></form>\n";

print "</td><td valign=top width=50%>\n";
@http = &find_config("http_access", $conf);
if (@http) {
	print "<h3>$text{'eacl_pr'}</h3>\n";
	print "<table border width=100%>\n";
	print "<tr $tb><td width=10%><b>$text{'eacl_act'}</b></td>\n";
	print "<td><b>$text{'eacl_acls1'}</b></td>\n";
	print "<td width=10%><b>$text{'eacl_move'}</b></td> </tr>\n";
	$hc = 0;
	foreach $h (@http) {
		@v = @{$h->{'values'}};
		if ($v[0] eq "allow") {
			$v[0] = $text{'eacl_allow'};
		} else {
			$v[0] = $text{'eacl_deny'};
		}
		print "<tr $cb>\n";
		print "<td><a href=\"http_access.cgi?index=$h->{'index'}\">",
		      "$v[0]</a></td>\n";
		print "<td>",&html_escape(join(' ', @v[1..$#v])),"</td>\n";
		print "<td>\n";
		if ($hc != @http-1) {
			print "<a href=\"move_http.cgi?$hc+1\">",
			      "<img src=images/down.gif border=0></a>";
			}
		else { print "<img src=images/gap.gif>"; }
		if ($hc != 0) {
			print "<a href=\"move_http.cgi?$hc+-1\">",
			      "<img src=images/up.gif border=0></a>";
			}
		print "</td></tr>\n";
		$hc++;
		}
	print "</table>\n";
	}
else {
	print "<b>$text{'eacl_nopr'}</b><br>\n";
	}
print "<a href=http_access.cgi?new=1>$text{'eacl_addpr'}</a>\n";
print "</td></tr><tr><td valign=top width=50%>\n";

@icp = &find_config("icp_access", $conf);
if (@icp) {
	print "<h3>$text{'eacl_icpr'}</h3>\n";
	print "<table border width=100%>\n";
	print "<tr $tb> <td width=10%><b>$text{'eacl_act'}</b></td>\n"; 
	print "<td><b>$text{'eacl_acls1'}</b></td>\n";
	print "<td width=10%><b>$text{'eacl_move'}</b></td> </tr>\n";
	$ic = 0;
	foreach $i (@icp) {
		@v = @{$i->{'values'}};
		if ($v[0] eq "allow") {
			$v[0] = $text{'eacl_allow'};
		} else {
			$v[0] = $text{'eacl_deny'};
		}
		print "<tr $cb>\n";
		print "<td><a href=\"icp_access.cgi?index=$i->{'index'}\">",
		      "$v[0]</a></td>\n";
		print "<td>",&html_escape(join(' ', @v[1..$#v])),"</td>\n";
		print "<td>\n";
		if ($ic != @icp-1) {
			print "<a href=\"move_icp.cgi?$ic+1\">",
			      "<img src=images/down.gif border=0></a>";
			}
		else { print "<img src=images/gap.gif>"; }
		if ($ic != 0) {
			print "<a href=\"move_icp.cgi?$ic+-1\">",
			      "<img src=images/up.gif border=0></a>";
			}
		print "</td></tr>\n";
		$ic++;
		}
	print "</table>\n";
	}
else {
	print "<b>$text{'eacl_noicpr'}</b><br>\n";
	}
print "<a href=icp_access.cgi?new=1>$text{'eacl_addicpr'}</a>\n";

print "</td></tr></table><p>\n";

print "<hr>\n";
&footer("", $text{'eacl_return'});

