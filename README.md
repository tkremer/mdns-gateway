# MDNS gateway DNS server

This is a DNS server that serves requests based on MDNS lookup results from avahi-daemon. It is not meant to be used standalone but rather as a backend server for dnsmasq or similar DNS servers to provide MDNS functionality to clients that don't have a working MDNS stack.

Contents:
- mdns-gateway.pl: The MDNS gateway DNS server
- mdns-gateway.dnsmasq.conf: configuration fragment for dnsmasq.
- avahi-resolve.pl: command line client to test avahi connectivity.
- hashdns-anyevent.pl: An old hash-based pseudorandom DNS server implementation. (for educational purposes only)

Requirements:
- avahi-daemon
- libanyevent-perl
- libanyevent-handle-udp-perl

