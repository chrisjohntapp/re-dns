#!/usr/bin/env python3

import sys
import dns.query
import dns.update
import dns.resolver
import dns.tsigkeyring

# This script makes the following assumptions:
# Hosts are not multi-homed;
# All networks are class C;
# All hostnames exist under same domain name;
# Hosts only need A records updated;

# TODO:
# Exception handling;

hostnames = [ 'foobar', 'barfoo' ]
domain_name = 'mps.lan'
production_network = '10.15.0'
dr_network = '10.95.0'
nameserver = '172.16.62.51'
tsigkeyname = 'tappy-bind'
tsigkey = '/lOHWPHv5B6QXKqsEcwWguuIOx+F8jqL1nK92DamiKAChAR60CgD3qI8N0iy2nr+hLIvBVdNcYIyav3JaQYdlg=='
keyalgorithm = 'hmac-sha512'

class Host:
    def __init__(self, hostname):
        self.hostname = hostname

    def get_current_arecords(self):
        response = dns.resolver.query(self.hostname, 'A')
        arecords = []
        for resp in response:
            arecords.append(resp.address) 
        return arecords

    def get_current_networks(self):
        arecords = self.get_current_arecords()
        networks = []
        for arec in arecords:
            # Remove the last octet of address. There's probably a better way.
            tmp1 = arec.split('.')
            tmp2 = tmp1.pop()
            netw = '.'.join(tmp2)
            networks.append(netw)
        return networks

    def validate_current_networks(self, category):
        def check_all_match(networks):
            # Check all class C nets are same as the first one.
            all(x == networks[0] for x in networks)

        def check_category(networks, category):
            all(x == category for x in networks)

        networks = self.get_current_networks()
        check_all_match(networks)
        check_category(networks, category)

    def update_records(self, ttl=300):
        arecords = self.get_current_arecords()
        update = dns.update.Update(domain_name, keyring=keyring, keyalgorithm=keyalgorithm)
        for arec in arecords:
            update.replace(self.hostname, ttl, 'A', new_arec)
        response = dns.query.tcp(update, nameserver)


keyring = dns.tsigkeyring.from_text({ tsigkeyname : tsigkey })

for hostname in hostnames:
    h = Host(hostname)
    h.validate_current_networks(production_network)
    h.update_records()
#    h.check_records() # If this fails, stop processing further hosts.


# Update a record -------------------------------
#update = dns.update.Update('laputa.', keyring=keyring, keyalgorithm=keyalgorithm)
#update.replace('foobar', 300, 'A', '10.10.10.10')
#response = dns.query.tcp(update, nameserver)


# Add a record ----------------------------------
#update = dns.update.Update('laputa.', keyring=keyring, keyalgorithm=keyalgorithm)
#update.add('foobar', 300, 'A', '10.20.30.40')
#
#response = dns.query.tcp(update, nameserver, timeout=10)
