#!/usr/bin/perl
# user_chooser.cgi
# This CGI generated the HTML for choosing a user or list of users.
# 
# Cumulus Firewall 
# Copyright (C) 2000  Øyvind Jelstad, Cumulus IT AS
# 
# $Id: object_viewer.cgi,v 1.2 2001/02/21 14:31:26 oyvind Exp $

require 'fwrap-lib.pl';

if (! $access{'vobject'}) { &error($text{'acl_vobject'} . ": ".$text{'no'} ) }

#&init_config();
#&ReadParse();
&header();

if ($in{'service'}) {
	       $objects = &get_objects( "servicefile" );			
}else {
		$objects = &get_objects;
}

$v = $objects->{$in{'object'}};
$v->listname("objects");

print "<h2> Definisjon av " . $v->name . " </h2>";
print "<pre>\n";

#$v->display;
print $v->txtout;

print "</pre>\n";

&footer("", $text{'erule_return'});

