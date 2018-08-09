#!/usr/bin/env python3

import sys
import dns.query
import dns.update
import dns.resolver
import dns.tsigkeyring

# This script makes the following assumptions:
# Hosts are not multi-homed;
# All networks are class C;
# Hosts only need A records updated;

hostnames = [ 'foobar', 'barfoo' ]
production_network = '10.15.0'
dr_network = '10.95.0'
tsigkey = '/lOHWPHv5B6QXKqsEcwWguuIOx+F8jqL1nK92DamiKAChAR60CgD3qI8N0iy2nr+hLIvBVdNcYIyav3JaQYdlg=='
nameserver = '172.16.62.51'

keyring = dns.tsigkeyring.from_text({ 'tappy-bind' : tsigkey })

class Host:
    def __init__(self, hostname):
        self.hostname = hostname

    def get_current_networks(self):
        response = dns.resolver.query(self.hostname, 'A')
        self.arecords = []
        for resp in response:
            self.arecords.append(resp.address) 
        self.networks = []
        for arec in self.arecords:
            tmp1 = arec.split('.')
            tmp2 = tmp1.pop()
            netw = '.'.join(tmp2)
            self.networks.append(netw)
        return self.networks

    def check_network_category(self, networks, category):
        """
        Yes this is checking all nets again when one would strictly do, but
        there's no harm in it and it might be useful if script is tweaked in
        future.
        """
        all(x == category for x in networks)

    def validate_current_network(self):
        def check_all_match(networks):
            # Check all class C nets are same as the first one.
            all(x == networks[0] for x in networks)

        networks = self.get_current_networks()
        check_all_match(networks)
        self.check_network_category(networks, production_network)


    def get_current_addresses(self):
        response = dns.resolver.query(self.hostname, 'A')
        self.arecords = []
        for r in response:
            self.arecords.append(r.address) 
        return self.arecords

    def create_new_addresses(self):
        pass

    def update_records(self):
        pass

for hostname in hostnames:
    h = Host(hostname)
    h.validate_current_network()
    h.get_current_addresses()
    h.create_new_addresses()
    h.update_records()
    h.check_records() # If this fails, stop processing further hosts.

# Query for A records ---------------------------
#answers = dns.resolver.query('drbunsen.phys.laputa', 'A')
#for a in answers:
#    print(a.address)

# Add a record ----------------------------------
#update = dns.update.Update('laputa.', keyring=keyring, keyalgorithm='hmac-sha512')
#update.add('foobar', 300, 'A', '10.20.30.40')
#
#response = dns.query.tcp(update, nameserver, timeout=10)


# Update a record -------------------------------
#update = dns.update.Update('laputa.', keyring=keyring, keyalgorithm='hmac-sha512')
#update.replace('foobar', 300, 'A', '10.10.10.10')
#response = dns.query.tcp(update, nameserver)

