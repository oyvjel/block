#!/usr/bin/perl
# 
# Cumulus Firewall 
# Copyright (C) 2000  Øyvind Jelstad, Cumulus IT AS
# 
# $Id: fwrap-lib.pl,v 1.2 2003/01/21 13:04:44 oyvind Exp $
#

$config{'scriptfile'} = "block";
$IPTABLES = ($config{'ipchains_path'}) ? $config{'ipchains_path'} : "/sbin/iptables"; 

require "../cfw/fw-lib.pl";
require '../cfw/obj-lib.pl';

$config{'scriptfile'} = $config{'bootloc'} ."/block";

1;
