#!/usr/bin/perl

# avahi_resolve.pl - command line avahi client for resolving hosts and IPs.

# Copyright (c) 2021 Thomas Kremer

# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 or 3 as
# published by the Free Software Foundation.

# external dependencies:
#   avahi-daemon, libanyevent-perl


# usage:
#   avahi_resolve.pl host.local
#   avahi_resolve.pl host.local 4
#   avahi_resolve.pl host.local 6
#   avahi_resolve.pl 192.168.0.1 r

use strict;
use warnings;
use AnyEvent;

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

  # sub resolve {
  #   my ($self,$target,$ver,$cb,$err) = @_;
  #   $ver //= "4";
  #   $ver = $ver eq "" ? "" :
  #          $ver eq "4" || $ver eq "6" ? "-IPV$ver" :
  #          die "bad IP version \"$ver\"";
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
    # my $guard = tcp_connect("unix/", $self->{socket}, sub {
      # if (!@_) {
      #   #print STDERR "could not connect: $!";
      #   $err->("Could not connect");
      #   delete $self->{guards}{$id} if defined $self;
      #   return;
      # }
      # my ($fh,$peer,$peerport,$retry) = @_;
      # my $handle;
      # my $res = 2;
      # my $content = "";
      # $handle = AnyEvent::Handle->new(
      #   fh => $fh,
        on_error => sub {
          my ($h,$fatal,$message) = @_;
          #print STDERR "ERROR\n";
          $h->destroy;
          $err->("IO Error ".(0+$!).": ".$message);
          delete $self->{guards}{$id} if defined $self;
        },
        on_eof => sub {
          my $handle = shift;
          # NOTE: This sub holds a reference to $handle.
          #$res = _parse_result($content,$cb,$err,$dbg);
          my $good = $cb->($content);
          if ($good && defined $self && $self->{cache_lifetime}) {
            $self->{cache}{$cmd} = [$content,time,
              AnyEvent->timer(after => $self->{cache_lifetime},cb => sub {
                delete $self->{cache}{$cmd} if defined $self;
              })];
          }
          # chomp $content;
          # if ($content =~ /^\+ (\d+) (\d+) (\S+) ([\d.]+|[\da-fA-F:]+)$|^-(\d+) (.*)$/) {
          #   # interface# protocol hostname ip
          #   $dbg->(defined($1) ? "Got \"$content\"\n" : "Error $5: $6");
          #   $cb->(defined($1) ? ($1,$2,$3,$4) : ());
          #   return 0;
          # } else {
          #   $err->("bad answer from avahi: \"$content\"\n");
          # }
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
      #$handle->push_write("RESOLVE-HOSTNAME$ver $target\n");
      # $handle->push_write($cmd."\n");
    # });
    my $guard = $handle;
    $id = "$guard";
    $self->{guards}{$id} = $guard;
    weaken($self);
  }
}

my $exit = AnyEvent->condvar;
my $target = shift//"host.local";
my $ipver = shift//"";

my $avahi = Avahi->new(debug => 1, timeout => 1, cache_lifetime => 20);

if ($ipver ne "r") {
  $avahi->resolve($target,$ipver,sub{
    my ($iface,$proto,$hostname,$ip) = @_;
    print "$hostname $ip\n" if @_;
    $exit->send(0);
  },sub{ print @_,"\n"; $exit->send(2);});
} else {
  $avahi->resolve_addr($target,sub{
    my ($iface,$proto,$hostname) = @_;
    print "$hostname $target\n" if @_;
    $exit->send(0);
  },sub{ print @_,"\n"; $exit->send(2);});
}

exit $exit->recv;

# # (echo "RESOLVE-HOSTNAME-IPV4 ranger.local"; sleep 3;) | socat - /run/avahi-daemon/socket 
# + 3 0 ranger.local 192.168.0.12
# # (echo "RESOLVE-HOSTNAME-IPV4 ranges.local"; sleep 3;) | socat - /run/avahi-daemon/socket 
# # (echo "RESOLVE-HOSTNAME-IPV4 ranges.local"; sleep 30;) | socat - /run/avahi-daemon/socket 
# -15 Timeout reached


