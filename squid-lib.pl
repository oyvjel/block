
$config{'aclfile'} = $config{'policypath'} ."/".$config{'acl'};

sub read_acl_file {
  open(SCRIPT, $config{'aclfile'});
# open(SCRIPT, "/etc/webmin/block/squid.acl");
  @lines=<SCRIPT>;
 close SCRIPT;
# @lines = grep(!/^#/, @lines);
return @lines;
}


sub parse_acl {
  local(%line, $tmpstr, $n);

  $tmpstr=$_[0];
  $n=$_[1];

    if (  $tmpstr =~ /^\s*(\S+)\s*(\S+)\s*(.*)$/) {
	$line{'nr'} = $n;
	$line{'name'} = $1;
	$line{'action'} = $2;
	$line{'values'} =  $3;
#	$line{'values'} = [ split(/\s+/, $3) ];
#	$line{'index'} = scalar(@get_config_cache);
#	push(@get_config_cache, \%dir);
	return \%line;
	
    }
return;  
}

sub parse_acl_file {
 local(@lines, @rv, $tmpstr, $i) ;
 @lines=&read_acl_file;
 
 for (my $n=0; $n<@lines; $n++) {
  $tmpstr=@lines[$n];
#     print "Linje $n: $tmpstr\n";
     next if ($tmpstr =~ /^#/);
     if ( $l = &parse_acl($tmpstr, $n) ){  
	 push(@rv, $l);
     }
 }

return @rv;
}

1;
