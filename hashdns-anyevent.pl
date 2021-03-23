#!/usr/bin/perl

# hasndns-anyevent.pl - example DNS server serving pseudorandom IPs.

# Copyright (c) 2014-2021 Thomas Kremer

# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 or 3 as
# published by the Free Software Foundation.

# external dependencies:
#   libanyevent-perl, libanyevent-handle-udp-perl


# usage:
#   ./hashdns-anyevent.pl
#   dig @127.0.0.1 -p 5355 +noedns +noadflag foo.ip.localdomain

# dnsmasq config:
# echo "server=/ip.localdomain/127.0.0.1#5355" > /etc/dnsmasq.d/hashdns.conf 

use strict;
use warnings;
use AnyEvent;
use AnyEvent::Handle::UDP;
#use IO::Socket::IP;
#use IO::Select;
use Digest::SHA;

my $udp_max_buffer = 8192;
my (%rec_types,%rec_types_inv);

my %sockopts = (
  Proto => "udp",
  #Listen => 5,
  LocalPort => 5355,
  ReuseAddr => 1,
  LocalAddr => "127.0.0.1" # LocalAddr for debugging
);

# my $sock = IO::Socket::IP->new(%sockopts);
# 
# #my $ep = pack_endpoint($ip,$port);
# 
# my $sel = IO::Select->new($sock);

sub hexdump {
  my $s = shift;
  my $addr = 0;
  while ($s =~ /\G(.{0,16})/gs) {
    my ($hex,$asc,$len) = ($1,$1,length($1));
    $hex =~ s/(.)/ sprintf "%02x ",ord($1) /ges;
    $asc =~ s/[\0-\x1f\x7f-\xff]/./gs;
    printf "%08x %-48s%s\n", $addr, $hex, $asc;
    $addr += $len;
  }
}

$| = 1;

my $rex = pack "C*", qw(1 0  0 1 0 0  0 0 0 0);
$rex = qr/^(..)(?:$rex([^\0]*)\0(..)\0\x01$)?/s;

sub unpack_host {
  my $s = shift;
  my @res;
  while (length($s) != 0) {
    my $len = ord(substr($s,0,1));
    return undef if (length($s) < $len+1);
    my $part = substr($s,1,$len);
    return undef if $part =~ /[^a-z0-9_-]/;
    push @res, $part;
    substr($s,0,$len+1) = "";
  }
  return join(".",@res);
}

sub mkanswer {
  my ($req,$ok,@ips) = @_;
  my $ret = 0x8180 + ($ok?0:3);
  my $res = $req;
  substr($res,2,2) = pack "n", $ret;
  substr($res,6,2) = pack "n", scalar(@ips);
  for (@ips) {
    my ($type,$class,$ttl,$length,$content) = (1,1,3600,0,"");
    if (ref($_) eq "HASH") {
      $type = $$_{type};
      $class = $$_{class} if exists $$_{class};
      $ttl = $$_{ttl} if exists $$_{ttl};
      $content = $$_{content} if exists $$_{content};
      $length = length($content);
    } elsif (ref($_) eq "SCALAR") {
      $content = $$_;
      $length = length($content);
      $type = $length == 4 ? $rec_types{A} :
              $length == 16 ? $rec_types{AAAA} : $rec_types{CNAME};
    } elsif (ref($_) eq "ARRAY") {
      $content = pack "C*", @$_;
      $length = @$_;
      $type = $length == 4 ? $rec_types{A} :
              $length == 16 ? $rec_types{AAAA} : undef;
      return undef unless defined $type;
    } elsif (/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
      $content = pack "C*", $1, $2, $3, $4;
      $length = 4;
      $type = $rec_types{A};
    } elsif (my @lits = /^(?:[\da-fA-F]{1,4}|::|:)+$/g) {
      @lits = grep $_ != ":", @lits;
      return undef if @lits > 8;
      my @fill = (0)x(8-@lits);
      @lits = map $_ eq "::" ? @fill : hex($_), @lits;
      return undef if @lits != 8;
      $content = pack "n[8]", @lits;
      $length = 16;
      $type = $rec_types{AAAA};
    }
    $res .= pack "n nn N n a*", 0xc00c, $type,$class,$ttl,$length,$content;
  }
  return $res;
#  $id 81 (80+3*$NXDOMAIN) 0 1 0 $results 0 0 0 0 $request
#  (c0 0c $type[u16be] $class[u16be]=1 $ttl[u32be] $length[u16be] $ip4)[$results]
}

sub parse_request {
  my $msg = shift;
  if ($msg =~ /$rex/) {
    my ($nonce,$packedhost,$type) = ($1,$2,$3);
    if (!defined $type) {
      # bad format. Probably EDNS. return FORMERR.
      return { raw => $nonce.("\0"x10), FORMERR => 1 };
    }
    $type = unpack "n", $type;
    my $host = unpack_host($packedhost);
    if (defined $host) {
      return { host => $host, type => $type, raw => $msg };
    }
  }
  return undef;
}
sub pack_answer {
  my $answer = shift;
  return mkanswer(@$answer);
}

my %supported_rectypes = map {$rec_types{$_} => 1} qw(A AAAA * NS TXT);
sub get_answer {
  my ($req,$cb) = @_;
  my ($host,$type,$msg) = @{$req}{qw(host type raw)};
  $cb->([$msg,0]),return unless $supported_rectypes{$type};
  #($type == $rec_types{A} || $type == $rec_types{AAAA} || $type == $rec_types{"*"} || $type == $rec_types{NS});
  # reply with an A record.
  #if ($host =~ /^([0-9a-f]{8})\.ip\.localdomain$/) {
    #my $packedip = pack "H*", $1;
  if ($host =~ /^(ns\.)?(([^.]+)\.ip\.localdomain)$/) {
    my $hash = Digest::SHA::sha1($3);
    my $lastbit = ord(substr($hash,-1,1)) & 1;
    my $packedip;
    if ($lastbit) {
      $packedip = substr($hash,0,4);
    } else {
      $packedip = substr($hash,0,16);
    }
    my @res = \$packedip;
    if ($type == $rec_types{NS}) {
      @res = ({
          type => $type,
          content => "\x02ns\xc0\x0c", # coded domain name
        });#,
      #\$packedip);
    } elsif ($type == $rec_types{TXT}) {
      my @txt = ("Hello World!","Your ad here!","This domain presented to you by $host");
      @res = map(+{
          type => $type,
          #content => substr($packedip,-1)."Hello World",
          content => pack "C/a*",$_,
        }, @txt);
    }
    $cb->([$msg,1,@res]);
    return;
  }
  $cb->([$msg,0]);
  return;
} 

my $exit = AnyEvent->condvar;

$SIG{INT} = sub { $exit->send(0); };

my $server = AnyEvent::Handle::UDP->new(
  bind => [@sockopts{qw(LocalAddr LocalPort)}],
  on_recv => sub {
    my ($msg,$handle,$client_addr) = @_;
    my $request = parse_request($msg);
    printf defined $request ?
      ("(%s %s %s)<\n",unpack("H*",$client_addr),$rec_types_inv{$request->{type}//""}//"undef",$request->{host}//"undef") :
      ("(%s invalid)<\n",$client_addr);
    hexdump($msg);
    return unless defined $request;
    if ($request->{FORMERR}) {
      my $packet = $request->{raw};
      substr($packet,2,2) = "\x81\x81";
      $handle->push_send($packet,$client_addr);
      return;
    }
    get_answer($request,sub {
      my $answer = shift;
      return unless defined $answer;
      my $packet = pack_answer($answer);
      printf "(%d)>\n", scalar(@$answer);
      hexdump($packet);
      $handle->push_send($packet,$client_addr);
    });
  }
);

my $ret = $exit->wait;
print "done.\n";
exit $ret;

# while(1) {
#   my @ready = $sel->can_read(1000);
#   if (@ready) {
#     my $ep = $sock->recv(my $msg,$udp_max_buffer,0) || die "recv: $!";
# 
#     print "<\n";
#     hexdump($msg);
#     my $request = parse_request($msg);
#     next unless defined $request;
#     get_answer($request,sub {
#       my $answer = shift;
#       return unless defined $answer;
#       my $packet = pack_answer($answer);
#       printf "(%d)>\n", scalar(@$answer);
#       hexdump($packet);
#       $sock->send($packet,0,$ep);
#     });
#   } # else no packet there, just a timeout.
# 
# } # loop forever.

# 00000000 76 a3 01 00 00 01 00 00 00 00 00 00 03 77 77 77 v............www
# 00000010 03 66 6f 6f 03 62 61 72 00 00 1c 00 01          .foo.bar.....
# 
# 00000000 af f3 01 00 00 01 00 00 00 00 00 00 03 77 77 77 .............www
# 00000010 03 66 6f 6f 03 62 61 72 0d 6c 61 6c 61 6c 61 6c .foo.bar.lalalal
# 00000020 61 6c 61 6c 61 6c 0c 64 64 64 73 64 73 64 73 64 alalal.dddsdsdsd
# 00000030 73 64 73 03 62 61 75 00 00 01 00 01             sds.bau.....
# 0000003c                                                 
# 
# 00000000 [$nonce[u16be] af f3]
#                01 00 00 01 00 00 00 00 00 00
#                ($lenbyte $name[$lenbyte])* 00
#                 $type[u16be] 00 01

# # answers:
# # NXDOMAIN:
#  8a a5 01 00 00 01 00 00 00 00 00 00 03 77 77 77 03 66 6f 6f 03 62 61 72 00 00 01 00 01
#  8a a5 81 83 00 01 00 00 00 00 00 00 03 77 77 77 03 66 6f 6f 03 62 61 72 00 00 01 00 01
#  $id 81 83 0 1 0 $results 0 0 0 0 $request
# 
# # NOERROR, www.heise.de.           3529    IN      A       193.99.144.85
#  6a 4a 01 00 00 01 00 00 00 00 00 00 03 77 77 77 05 68 65 69 73 65 02 64 65 00 00 01 00 01
#  6a 4a 81 80 00 01 00 01 00 00 00 00 03 77 77 77 05 68 65 69 73 65 02 64 65 00 00 01 00 01 c0 0c 00 01 00 01 00 00 0d c9 00 04 c1 63 90 55
#  $id 81 80 0 1 0 $results 0 0 0 0 $request
#  c0 0c 00 01 00 01 00 00 0d c9 00 04 $ip4
# 
# 
# # NOERROR, www.heise.de.           3403    IN      AAAA    2a02:2e0:3fe:1001:7777:772e:2:85
#  e0 6d 01 00 00 01 00 00 00 00 00 00 03 77 77 77 05 68 65 69 73 65 02 64 65 00 00 1c 00 01
#  e0 6d 81 80 00 01 00 01 00 00 00 00 03 77 77 77 05 68 65 69 73 65 02 64 65 00 00 1c 00 01 c0 0c 00 1c 00 01 00 00 0d 4b 00 10 2a 02 02 e0 03 fe 10 01 77 77 77 2e 00 02 00 85
#  $id 81 80 0 1 0 $results 00 00 00 00 $request
#  c0 0c 00 1c 00 01 00 00 0d 4b 00 10 $ip6
# 
# 
#  e0 6d 01 00 00 01 00 00 00 00 00 00 03 77 77 77 05 68 65 69 73 65 02 64 65 00 00 1c 00 01
#  e0 6d 81 80 00 01 00 01 00 00 00 00 03 77 77 77 05 68 65 69 73 65 02 64 65 00 00 1c 00 01
#  $id 81 80  0 1 0 $results 0 0 0 0 $request
#  c0 0c 00 1c 00 01 00 00 0d 4b 00 10 $ip6
# 
# # NOERROR, www.google.com  220 IN A 173.194.69.{147,99,103,105,106,104}
#  23 32 01 00 00 01 00 00 00 00 00 00 03 77 77 77 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01
#   23 32 81 80 00 01 00 06 00 00 00 00 03 77 77 77 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01 c0 0c 00 01 00 01 00 00 00 dc 00 04 ad c2 45 93 c0 0c 00 01 00 01 00 00 00 dc 00 04 ad c2 45 63 c0 0c 00 01 00 01 00 00 00 dc 00 04 ad c2 45 67 c0 0c 00 01 00 01 00 00 00 dc 00 04 ad c2 45 69 c0 0c 00 01 00 01 00 00 00 dc 00 04 ad c2 45 6a c0 0c 00 01 00 01 00 00 00 dc 00 04 ad c2 45 68
#   $id 81 80  0 1 0 $results 0 0 0 0 $request 
#   c0 0c 00 01 00 01 00 00 00 dc 00 04 $ip4
#   c0 0c 00 01 00 01 00 00 00 dc 00 04 $ip4
#   c0 0c 00 01 00 01 00 00 00 dc 00 04 $ip4
#   c0 0c 00 01 00 01 00 00 00 dc 00 04 $ip4
#   c0 0c 00 01 00 01 00 00 00 dc 00 04 $ip4
#   c0 0c 00 01 00 01 00 00 00 dc 00 04 $ip4
# 
#           c0 0c 00 01 00 01 00 00 0d c9 00 04 $ip4
#           c0 0c 00 1c 00 01 00 00 0d 4b 00 10 $ip6
#   $id 81 (80+3*$NXDOMAIN) 0 1 0 $results 0 0 0 0 $request
#   (c0 0c $type[u16be] $class[u16be]=1 $ttl[u32be] $length[u16be] $ip4)[$results]
# 

# heise.de NS: 5x answer (NS -> ns.heise.de etc), 5x additional (ns.heise.de -> 193.99.145.37 etc)

#  b1 86 01 00 00 01 00 00 00 00 00 00 05 68 65 69 73 65 02 64 65 00 00 02 00 01
#  b1 86 81 80 00 01 00 05 00 00 00 05 05 68 65 69 73 65 02 64 65 00 00 02 00 01 c0 0c 00 02 00 01 00 00 0e 10 00 16 03 6e 73 32 0c 70 6f 70 2d 68 61 6e 6e 6f 76 65 72 03 6e 65 74 00 c0 0c 00 02 00 01 00 00 0e 10 00 0e 02 6e 73 08 70 6c 75 73 6c 69 6e 65 c0 12 c0 0c 00 02 00 01 00 00 0e 10 00 05 02 6e 73 c0 0c c0 0c 00 02 00 01 00 00 0e 10 00 07 02 6e 73 01 73 c0 4b c0 0c 00 02 00 01 00 00 0e 10 00 12 02 6e 73 0c 70 6f 70 2d 68 61 6e 6e 6f 76 65 72 c0 12 c0 48 00 01 00 01 00 00 0b 4d 00 04 d4 13 30 0e c0 62 00 01 00 01 00 00 03 df 00 04 c1 63 91 25 c0 73 00 01 00 01 00 00 00 a9 00 04 d4 13 28 0e c0 86 00 01 00 01 00 00 03 05 00 04 c1 62 01 c8 c0 26 00 01 00 01 00 00 8d 7a 00 04 3e 30 43 42
# 
#  $id 81 80 0 1 0 $results 00 $auth_res 00 $additional_res
#  $request[ 05 68 65 69 73 65  02 64 65  00    00 02 00 01]
#   c0 0c 00 02 00 01 00 00 0e 10 00 16 03 6e 73 32 0c 70 6f 70 2d 68 61 6e 6e 6f 76 65 72 03 6e 65 74 00
#   c0 0c 00 02 00 01 00 00 0e 10 00 0e 02 6e 73 08 70 6c 75 73 6c 69 6e 65 c0 12 
#   c0 0c 00 02 00 01 00 00 0e 10 00 05 02 6e 73 c0 0c 
#   c0 0c 00 02 00 01 00 00 0e 10 00 07 02 6e 73 01 73 c0 4b 
#   c0 0c 00 02 00 01 00 00 0e 10 00 12 02 6e 73 0c 70 6f 70 2d 68 61 6e 6e 6f 76 65 72 c0 12
#   c0 48 00 01 00 01 00 00 0b 4d 00 04 d4 13 30 0e
#   c0 62 00 01 00 01 00 00 03 df 00 04 c1 63 91 25
#   c0 73 00 01 00 01 00 00 00 a9 00 04 d4 13 28 0e
#   c0 86 00 01 00 01 00 00 03 05 00 04 c1 62 01 c8
#   c0 26 00 01 00 01 00 00 8d 7a 00 04 3e 30 43 42

# c0 XX == reference to index XX in udp package.
#  --> c00c == reference to question.
# 00 == reference to empty string.
#

BEGIN {
  # FYI, from wikipedia (last ones are special):
  %rec_types = qw(
    A           1
    AAAA        28
    AFSDB       18
    APL         42
    CAA         257
    CERT        37
    CNAME       5
    DHCID       49
    DLV         32769
    DNAME       39
    DNSKEY      48
    DS          43
    HIP         55
    IPSECKEY    45
    KEY         25
    KX          36
    LOC         29
    MX          15
    NAPTR       35
    NS          2
    NSEC        47
    NSEC3       50
    NSEC3PARAM  51
    PTR         12
    RRSIG       46
    RP          17
    SIG         24
    SOA         6
    SPF         99
    SRV         33
    SSHFP       44
    TA          32768
    TKEY        249
    TLSA        52
    TSIG        250
    TXT         16


    *           255
    AXFR        252
    IXFR        251
    OPT         41
  );
  %rec_types_inv = reverse %rec_types;
}
