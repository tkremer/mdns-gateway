#!/usr/bin/perl

# mdns-gateway.pl - DNS server serving MDNS lookup results.

# Copyright (c) 2014-2021 Thomas Kremer

# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 or 3 as
# published by the Free Software Foundation.

# external dependencies:
#   avahi-daemon, libanyevent-perl, libanyevent-handle-udp-perl


# usage:
#   ./mdns-gateway.pl
#   dig @127.0.0.1 -p 5354 +noedns +noadflag somehost.local

# dnsmasq config:
# echo "server=/local/127.0.0.1#5354" > /etc/dnsmasq.d/mdns-gateway.conf 


use strict;
use warnings;
use AnyEvent;

my $bind = [ "127.0.0.1", 5354 ];

# sub hexdump {
#   my $s = shift;
#   my $addr = 0;
#   my $res = "";
#   while ($s =~ /\G(.{0,16})/gs) {
#     my ($hex,$asc,$len) = ($1,$1,length($1));
#     $hex =~ s/(.)/ sprintf "%02x ",ord($1) /ges;
#     $asc =~ s/[\0-\x1f\x7f-\xff]/./gs;
#     $res .= sprintf "%08x %-48s%s\n", $addr, $hex, $asc;
#     $addr += $len;
#   }
#   return $res;
# }
# $| = 1;

{
  package DNSServer;
  use AnyEvent;
  use AnyEvent::Handle::UDP;
  #use Digest::SHA;

  our (%rec_types,%rec_types_inv);

  # We're picky about what we accept.
  # A bit too picky for some regular tools it seems...
  # We're responding to EDNS with a FORMERR as per spec now.
  # DONE: EDNS support - at least we're accepting EDNS queries now. Answers are still regular DNS.
  # TODO: respect packet size limits.
  # TODO: enforce domain length limits.
  # TODO: support label compression in parsing (though probably only possible in insane requests).

  # #my $request_rex = pack "C*", qw(1 0  0 1 0 0  0 0 0 0);
  # #                 flags, #questions, #answers, #auths, #adds
  # my $request_rex = pack "n*", 0x0100, 1,0,0,0;
  # #                  ident,...,       host,          type,class
  # $request_rex = qr/^(..)(?:$request_rex([^\0]{0,254})\0(..)\0\x01$)?/s;

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

  sub unpack_host {
    my $s = shift;
    return undef if length($s) > 254; # max domain name length exceeded
    my @res = unpack "(C/a*)*", $s;
    if (@res) {
      my $l = length($res[-1]);
      # truncated last segment:
      return undef unless ord(substr($s,-$l-1,1)) == $l;
    }
    for (@res) {
      return undef if length > 63; # max label size exceeded
      return undef if /[^-a-zA-Z0-9]/; # bad character in domain name
      $_ = lc($_); # RFC 4343: DNS Case Insensitivity Clarification
    }
    # my @res;
    # while (length($s) != 0) {
    #   my $len = ord(substr($s,0,1));
    #   return undef if (length($s) < $len+1);
    #   my $part = substr($s,1,$len);
    #   return undef if $part =~ /[^a-z0-9_-]/;
    #   push @res, $part;
    #   substr($s,0,$len+1) = "";
    # }
    return join(".",@res);
  }

  # $answer should define "ok" and answers. (default ok=false, answers=[])
  # It may also define authorities, additionals and RCODE
  # RCODE is numeric and defaults to ok?NOERROR:NXDOMAIN.
  # authorities and additionals default to empty arrays.
  # answers, authorities and additionals are array-refs containing resource
  #  records in one of the following forms:
  #   hashref: { type => 0+..., class => 0+..., ttl => 0+..., content => "..."}
  #   scalar ref: \$content of 4 or 16 characters, will be an A or AAAA record.
  #   array ref: \@bytes of 4 or 16 elements, will be an A or AAAA record.
  #   string representation of an IPv4 or IPv6 address.
  # The content of the RR is used verbatim, no label compression is attempted.
  sub pack_answer {
    my ($request,$answer) = @_;
    my $req_raw = $request->{raw};
    #  return mkanswer($$answer{request}//$req_raw,@$answer{qw(ok answers)});
    #}
    #sub mkanswer {
    #  my ($req,$ok,$ips) = @_;
    my $ok = $answer->{ok};
    my @replies = @$answer{qw(answers authorities additionals)};
    $_ //= [] for @replies;
    my $edns = $answer->{edns};
    if ($request->{edns} && $edns) {
      my ($pl,$xrc,$opt) = (4096,0,undef);
        # FIXME: xrc is xrcode,version and flags
      ($pl,$xrc,$opt) = @{$answer->{edns}}{qw(payload_size xrcode options)}
        if ref $edns;
      my $rr = {
        name    => "\0",
        type    => $rec_types{OPT},
        class   => $pl,
        ttl     => $xrc,
        content => pack "(n n/a*)*", %{$opt//{}},
      };
      push @{$replies[2]}, $rr;
    }
    my $ret = 0x8180 + ($answer->{RCODE} // ($ok?0:3));
    my $res = $req_raw;
    substr($res,2,2) = pack "n", $ret;
    substr($res,6,6) = pack "n3", map scalar(@$_), @replies;
    for (map @$_, @replies) {
      my ($type,$class,$ttl,$length,$content) = (1,1,60,0,"");
      my $name = pack "n", 0xc00c;
      if (ref($_) eq "HASH") {
        $type = $$_{type};
        $name = $$_{name} if exists $$_{name};
        $class = $$_{class} if exists $$_{class};
        $ttl = $$_{ttl} if exists $$_{ttl};
        $content = $$_{content} if exists $$_{content};
        $length = length($content);
        if (ref $name eq "ARRAY") {
          $name = pack("(C/a*)*", @$name)."\0";
        } elsif (ref $name eq "SCALAR") {
          $name = pack("(C/a*)*", split /\./,$$name)."\0";
        }
        die "RR needs a type" unless defined $type;
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
        die "bad IP length" unless defined $type;
      } elsif (/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
        $content = pack "C*", $1, $2, $3, $4;
        $length = 4;
        $type = $rec_types{A};
      } elsif (/^(?:[\da-fA-F]{1,4}|::|:)+$/) {
        my @lits = /\G(?:[\da-fA-F]{1,4}|::|:)/g;
        #print STDERR join(",",map "<$_>", @lits),"\n";
        @lits = grep $_ ne ":", @lits;
        die "too many IPv6 parts" if @lits > 8;
        my @fill = (0)x(8-@lits);
        @lits = map $_ eq "::" ? @fill : hex($_), @lits;
        die "too many IPv6 double colons" if @lits != 8;
        $content = pack "n[8]", @lits;
        $length = 16;
        $type = $rec_types{AAAA};
      } else {
        die "invalid IP format";
      }
      $res .= pack "a* nn N n a*", $name,$type,$class,$ttl,$length,$content;
    }
    return $res;
#  $id 81 (80+3*$NXDOMAIN) 0 1 0 $results 0 0 0 0 $request
#  (c0 0c $type[u16be] $class[u16be]=1 $ttl[u32be] $length[u16be] $ip4)[$results]
  }

  sub parse_request {
    my $msg = shift;
    return undef if length($msg) < 12;
    my ($nonce,$flags,@sections) = unpack "a2 n5", $msg;
    return undef if $flags & 0x8000; # response from someone else.
    my ($minflags,$badflags) = (0x0000,0xe000); # query|QUERY
      # should we disallow response bits?
    my $formerr = { raw => $nonce.("\0"x10), FORMERR => 1 };
    return $formerr if ~$flags & $minflags || $flags & $badflags
         || ($sections[0] != 1) || $sections[1] || $sections[2];
    my $secdata = substr($msg,12);
    my $in_question = 1;
    my $rawlen;
    for (@sections) {
      my @entries;
      for (1..$_) {
        my @labels;
        my $l = 1;
        while($l) {
          return $formerr unless length $secdata;
          $l = unpack "C", $secdata;
          substr($secdata,0,1) = "";
          if ($l & 0xc0) {
            return $formerr if (~$l & 0xc0);
            return $formerr; # because we can't handle these yet.
            push @labels, $l;
            last;
          }
          return $formerr unless length($secdata) >= $l;
          push @labels, substr($secdata,0,$l);
          substr($secdata,0,$l) = "";
        }
        my @params = eval {
          unpack $in_question ? "nn" : "nnN n/a*", $secdata;
        };
        return $formerr if $@;
        $l = $in_question ? 4 : 10+length($params[-1]//"");
        return $formerr unless length($secdata) >= $l;
        substr($secdata,0,$l) = "";
        die "something slipped through" unless @labels && $labels[-1] eq "";
        pop @labels;
        my $name = join ".",
          map lc($_) =~ s/([^-a-z0-9])/sprintf "\\x%02x", ord($1)/gers, @labels;
        my @vars = (qw(labels name type class),$in_question?():qw(ttl rdata));
        my %entry;
        @entry{@vars} = (\@labels,$name,@params);
        push @entries, \%entry;
      }
      if ($in_question) {
        $in_question = 0;
        $rawlen = length($msg)-length($secdata);
      }
      $_ = \@entries;
    }
    my @opt = grep $_->{type} == $rec_types{OPT}, @{$sections[3]};
    return $formerr
      if $secdata ne "" || $sections[0][0]{class} != 1 || @opt > 1;
    my $res = { raw => substr($msg,0,$rawlen),
             question => $sections[0][0],
             additionals => $sections[3],
             sections => \@sections,
             host => $sections[0][0]{name},
             type => $sections[0][0]{type}
           };
    if (@opt) {
      return $formerr unless $opt[0]{name} eq "";
      my ($payload_size,$xRCODE,$data) = @{$opt[0]}{qw(class ttl rdata)};
      my %options = eval { unpack "(n n/a*)*", $data; };
      return $formerr if $@;
      $res->{edns} = { payload_size => $payload_size,
                       xrcode => $xRCODE,
                       options => \%options
                     };
    }
    #use Data::Dumper;
    #print STDERR Dumper($res->{sections});
    return $res;
  }

  # sub parse_request_old {
  #   my $msg = shift;
  #   if ($msg =~ /$request_rex/) {
  #     my ($nonce,$packedhost,$type) = ($1,$2,$3);
  #     if (!defined $type) {
  #       # bad format. Probably EDNS. return FORMERR.
  #       return { raw => $nonce.("\0"x10), FORMERR => 1 };
  #     }
  #     $type = unpack "n", $type;
  #     my $host = unpack_host($packedhost);
  #     if (defined $host) {
  #       return { host => $host, type => $type, raw => $msg };
  #     }
  #   }
  #   return undef;
  # }

  # $resolver = mapped_resolver([
  #   [qr/^.*\.some\.domain$/,$resolver1]
  #   [qr/^.*\.some\.other\.domain$/,["A","AAAA"],$resolver2]
  #   [qr/^.*\.domain$/,"TXT",$resolver3]
  #   [qr/^.*\.another\.domain$/,sub{$_[1] eq "foo.another.domain"},$resolver4]
  #   [qr/^.*\.another\.domain$/,sub{$_[0] == $rec_types{A}},$resolver5]
  # ]);
  sub mapped_resolver {
    my ($map) = @_;
    my @rawmap = @$map;
    for (@rawmap) {
      $_ = [qr/.*/,undef,$_],next if ref eq "CODE";
      die "need an array ref" if ref ne "ARRAY";
      die "wrong number of elements" if @$_ != 2 && @$_ != 3;
      my $rex = $$_[0];
      $rex = qr/^$rex$/ if ref $rex eq "";
      my $handler = $$_[-1];
      die "need handler" unless ref $handler eq "CODE";
      my $typesub = undef;
      if (@$_ == 3) {
        $typesub = $$_[1];
        $typesub = undef if !$typesub;
        # TODO: convert rectypes from name to numeric.
        $typesub = [$typesub] if ref $typesub eq "";
        $typesub = [ grep $typesub->{$_}, keys %$typesub ]
          if ref $typesub eq "HASH";
        #$typesub = { map {$_ => 1} @$typesub } if ref $typesub eq "ARRAY";
        if (ref $typesub eq "ARRAY") {
          my %h = map {($rec_types{$_}//$_) => 1} @$typesub;
          $typesub = sub { return $h{$_[0]}; };
        }
      }
      $_ = [$rex,$typesub,$handler];
    }
    return sub {
      my ($req,$cb,$err) = @_;
      my ($host,$type,$msg) = @{$req}{qw(host type raw)};
      for (@$map) {
        my $rex = $_->[0];
        my $typesub = $_->[1];
        if ($host =~ /$rex/ && (!$typesub || $typesub->($type,$host))) {
          return $_->[1]($req,$cb,$err);
        }
      }
      $cb->({ ok => 0 });
      return;
    };
  }

  # my %supported_rectypes = map {$rec_types{$_} => 1} qw(A AAAA * NS TXT);
  # sub get_answer {
  #   my ($req,$cb,$err) = @_;
  #   my ($host,$type,$msg) = @{$req}{qw(host type raw)};
  #   #($type == $rec_types{A} || $type == $rec_types{AAAA} || $type == $rec_types{"*"} || $type == $rec_types{NS});
  #   # reply with an A record.
  #   #if ($host =~ /^([0-9a-f]{8})\.ip\.localdomain$/)
  #     #my $packedip = pack "H*", $1;
  #   if ($host =~ /^(ns\.)?(([^.]+)\.ip\.localdomain)$/) {
  #     $cb->({ ok => 1 }),return unless $supported_rectypes{$type};
  #     my $hash = Digest::SHA::sha1($3);
  #     my $lastbit = ord(substr($hash,-1,1)) & 1;
  #     my $packedip;
  #     if ($lastbit) {
  #       $packedip = substr($hash,0,4);
  #     } else {
  #       $packedip = substr($hash,0,16);
  #     }
  #     my @res = \$packedip;
  #     if ($type == $rec_types{NS}) {
  #       @res = ({
  #           type => $type,
  #           content => "\x02ns\xc0\x0c", # coded domain name
  #         });#,
  #       #\$packedip);
  #     } elsif ($type == $rec_types{TXT}) {
  #       my @txt = ("Hello World!","Your ad here!","This domain presented to you by $host");
  #       @res = map(+{
  #           type => $type,
  #           #content => substr($packedip,-1)."Hello World",
  #           content => pack "C/a*",$_,
  #         }, @txt);
  #     }
  #     $cb->({ ok => 1, answers => \@res});
  #     return;
  #   }
  #   $cb->({ ok => 0 });
  #   return;
  # }

  sub new {
    my ($class,$bind,$resolver,$err) = @_;
    $bind //= ["127.0.0.1",5354];
    $resolver //= mapped_resolver([]);#\&get_answer;
    $err //= sub {};
    my $server = AnyEvent::Handle::UDP->new(
      bind => $bind,
      on_recv => sub {
        my ($msg,$handle,$client_addr) = @_;
        my $request = parse_request($msg);
        #printf STDERR defined $request ?
        #  ("(%s %s %s)<\n",unpack("H*",$client_addr),$rec_types_inv{$request->{type}},$request->{host}) :
        #  ("(%s invalid)<\n",$client_addr);
        #print STDERR main::hexdump($msg);
        return unless defined $request;
        if ($request->{FORMERR}) {
          my $packet = pack_answer($request,{ RCODE => 1 });
          $handle->push_send($packet,$client_addr);
          return;
        }

        $resolver->($request,sub {
          my $answer = shift;
          return unless defined $answer;
          eval {
            $answer->{edns} = 1;
            my $packet = pack_answer($request,$answer);
            #printf STDERR "(%d)>\n", scalar(@{$answer->{answers}//[]});
            #print STDERR main::hexdump($packet);
            $handle->push_send($packet,$client_addr);
          };
          if ($@) {
            $err->($@);
          }
        },$err);
      }
    );
    return $server; # TODO: bless?
  }
}

##########

{
  package Avahi;
  use Scalar::Util qw(weaken);
  use AnyEvent;
  use AnyEvent::Handle;
  my $default_sock_file = "/run/avahi-daemon/socket";

  # cb->(interface#,protocol,host,ip)
  # err->(message)
  # dbg->(message)

  # give cache_lifetime a positive value to enable the cache.
  sub new {
    my ($class,%args) = @_;
    $args{socket} //= $default_sock_file;
    $args{timeout} //= 10;
    $args{guards} = {};
    $args{cache} = {};
    $args{dbg} //= sub { print @_,"\n"; } if $args{debug};
    $args{$_} //= sub{} for qw(cb err dbg);
    die "socket does not exist" unless -S $args{socket} || $args{allow_bad_socket};
    return bless \%args, ref $class || $class;
  }

  sub resolve {
    my ($self,$target,$ver,$cb,$err) = @_;
    $ver //= "4";
    $ver = $ver eq "" ? "" :
           $ver eq "4" || $ver eq "6" ? "-IPV$ver" :
           die "bad IP version \"$ver\"";
    $cb //= $self->{cb};
    $err //= $self->{err};
    my $dbg = $self->{dbg};
    $self->command(
      "RESOLVE-HOSTNAME$ver $target",
      sub {
        my $content = shift;
        chomp $content;
        if ($content =~ /^\+ (\d+) (\d+) (\S+) ([\d.]+|[\da-fA-F:]+)$|^-(\d+) (.*)$/) {
          # interface# protocol hostname ip
          $dbg->(defined($1) ? "Got \"$content\"\n" : "Error $5: $6");
          $cb->(defined($1) ? ($1,$2,$3,$4) : ());
          return 0;
        } else {
          $err->("bad answer from avahi: \"$content\"\n");
        }
      },
      $err
    );
  }

  sub resolve_addr {
    my ($self,$target,$cb,$err) = @_;
    $cb //= $self->{cb};
    $err //= $self->{err};
    my $dbg = $self->{dbg};
    $self->command(
      "RESOLVE-ADDRESS $target",
      sub {
        my $content = shift;
        chomp $content;
        if ($content =~ /^\+ (\d+) (\d+) (\S+)$|^-(\d+) (.*)$/) {
          # interface# protocol hostname
          $dbg->(defined($1) ? "Got \"$content\"\n" : "Error $4: $5");
          $cb->(defined($1) ? ($1,$2,$3) : ());
          return defined($1) ? 1 : 0; # only cache positive results
        } else {
          $err->("bad answer from avahi: \"$content\"\n");
          return 0; # don't cache clear errors.
        }
      },
      $err
    );
  }

  sub command {
    my ($self,$cmd,$cb,$err) = @_;
    $cb //= $self->{cb};
    $err //= $self->{err};
    my $dbg = $self->{dbg};
    my $timeout = $self->{timeout};
    my $cache_entry = $self->{cache}{$cmd};
    if (defined $cache_entry) {
      $cb->($cache_entry->[0]);
      return;
      #return if time > $cache_entry->[1]+$cache_lifetime/2;
      #$cb = sub{};
      # TODO: better cache management: if an entry is middle-aged, go on and
      # renew it even though we already returned it.
      #  - but only if it's a positive result, which only $cb knows...
    }
    my $id;
    my $content = "";
    my $handle = AnyEvent::Handle->new(
      connect => ["unix/",$self->{socket}],
      on_connect_error => sub {
        my ($handle,$message) = @_;
        $err->("Could not connect: Error ".(0+$!).": $message");
        delete $self->{guards}{$id} if defined $self;
        $handle->destroy;
        return;
      },
      on_connect => sub {
        my ($handle,$peer,$peerport,$retry) = @_;
        $handle->push_write($cmd."\n");
      },
      on_error => sub {
        my ($h,$fatal,$message) = @_;
        #print STDERR "ERROR\n";
        $h->destroy;
        $err->("IO Error ".(0+$!).": ".$message);
        delete $self->{guards}{$id} if defined $self;
      },
      on_eof => sub {
        my $handle = shift;
        my $good = $cb->($content);
        if ($good && defined $self && $self->{cache_lifetime}) {
          $self->{cache}{$cmd} = [$content,time,
            AnyEvent->timer(after => $self->{cache_lifetime},cb => sub {
              delete $self->{cache}{$cmd} if defined $self;
            })];
        }
        delete $self->{guards}{$id} if defined $self;
        $handle->destroy;
      },
      on_read => sub {
        my $h = shift;
        $content .= $h->{rbuf};
        $h->{rbuf} = "";
        if (length $content > 8192) {
          # max buffer.
          $h->destroy;
          $err->("Buffer overflow");
        }
      },
      timeout => $timeout
    );
    my $guard = $handle;
    $id = "$guard";
    $self->{guards}{$id} = $guard;
    weaken($self);
  }
}

##########

my $avahi = Avahi->new(debug => 0, timeout => 2, cache_lifetime => 20);

my %fallback_cache;
my $fallback_cache_lifetime = 86400;

my $avahi_prune_timer = AnyEvent->timer(
  interval => $fallback_cache_lifetime/2, cb => sub {
  my $oldtime = time-$fallback_cache_lifetime;
  for (keys %fallback_cache) {
    delete $fallback_cache{$_} if $fallback_cache{$_}[1] < $oldtime;
  }
});

#         mname,rname,serial,refresh,retry,expire,ttl
my $soa = ["nic.local","postmaster.nic.local",1,600,300,1200,60];
$_ = pack "(C/a*)*", split(/\./),"" for @$soa[0,1];
$soa = pack "a* a* N5", @$soa;

sub avahi_resolver {
  my ($req,$cb,$err) = @_;
  $err //= sub {};
  my ($host,$type,$msg) = @{$req}{qw(host type raw)};
  if ($host =~ /^[-.\w]{1,64}\.local$/) {
    my $ipver =
      $type == $DNSServer::rec_types{"*"}  ? ""  :
      $type == $DNSServer::rec_types{A}    ? "4" :
      $type == $DNSServer::rec_types{AAAA} ? "6" : undef;

    if (!defined $ipver) {
      my @res;
      if ($type == $DNSServer::rec_types{TXT}) {
        my @txt = ("dns entry made by mdns-gateway");
        @res = map(+{ type => $type, content => pack("C/a*",$_) }, @txt);
      }
      $cb->({ ok => 1, answers => \@res});
      return;
    }

    my $key = $ipver."/".$host;
    my $entry = $fallback_cache{$key};
    $avahi->resolve($host,$ipver,sub {
      my ($iface,$proto,$hostname,$ip) = @_;
      if (@_) {
        #print STDERR "<$hostname,$ip>\n";
        $cb->({ ok => 1, answers => [$ip]});
        $fallback_cache{$key} = [$ip,time];
      } elsif (defined $entry) {
        $cb->({ ok => 1, answers => [$entry->[0]]});
        delete $fallback_cache{$key}
          if $entry->[1] < time-$fallback_cache_lifetime;
      } else {
        $cb->({ ok => 0 });
      }
    },sub {
      my $msg = shift;
      if (defined $entry) {
        $cb->({ ok => 1, answers => [$entry->[0]]});
        delete $fallback_cache{$key}
          if $entry->[1] < time-$fallback_cache_lifetime;
      } else {
        $cb->({ ok => 0 });
      }
      print STDERR "R $host: $msg\n" if $msg !~ /Connection timed out$/;
    });

  } elsif ($host eq "local") {
    # SOA requests.
    my @res;
    if ($type == $DNSServer::rec_types{"SOA"}) {
      @res = ({ type => $type, content => $soa });
    }
    $cb->({ ok => 1, answers => \@res });
  } else {
    $cb->({ ok => 0 });
  }
  return;
}

#  $avahi->resolve_addr($target,sub{
#    my ($iface,$proto,$hostname) = @_;
#    print "$hostname $target\n" if @_;
#    $exit->send(0);
#  },sub{ print @_,"\n"; $exit->send(2);});



my $exit = AnyEvent->condvar;

$SIG{INT} = sub { $exit->send(0); };

my $server = DNSServer->new($bind,\&avahi_resolver);

my $ret = $exit->recv;
#print "done.\n";
exit $ret;


