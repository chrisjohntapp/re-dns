#!/usr/bin/env python3

import os
import sys
import logging
import dns 

# This script makes the following assumptions:
# Hosts are not multi-homed;
# All networks are class C;
# All hostnames exist under same domain name;
# Hosts only need A records updated;

# TODO:
# Logging;
# Exception handling;
# Add comments;
# Use ipaddress module for networks/ips;

hostnames = [ 'foobar', 'barfoo' ]
domain_name = 'laputa'
production_network = '172.16.62'
dr_network = '10.95.0'
nameserver = '172.16.62.51'
tsigkeyname = 'tappy-bind'
tsigkey = '/lOHWPHv5B6QXKqsEcwWguuIOx+F8jqL1nK92DamiKAChAR60CgD3qI8N0iy2nr+hLIvBVdNcYIyav3JaQYdlg=='
keyalgorithm = 'hmac-sha512'
loglevel = 'INFO'

class Host:
    def __init__(self, hostname):
        self.hostname = hostname
        logger.info("Created {}.".format(self.hostname))

    def get_current_arecords(self):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ nameserver ]
        response = dns.resolver.query(
            "{}.{}".format(self.hostname, domain_name), 'A')
        arecords = []
        [ arecords.append(resp.address) for resp in response ]
        return arecords

    def get_current_networks(self):
        arecords = self.get_current_arecords()
        # Remove the last octet of address(es).
        networks = []
        [ networks.append('.'.join(arec.split('.')[-4:-1])) for arec in arecords ]
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

    def replace_records(self, new_ip, ttl=300):
        update = dns.update.Update(
            domain_name, keyring=keyring, keyalgorithm=keyalgorithm)
        update.replace(self.hostname, ttl, 'A', new_ip)
        dns.query.tcp(update, nameserver)
 
    def add_record(self, new_ip, ttl=300):
        update = dns.update.Update(
            domain_name, keyring=keyring, keyalgorithm=keyalgorithm)
        update.add(self.hostname, ttl, 'A', new_ip)
        dns.query.tcp(update, nameserver)

    def update_all_records(self):
        def create_new_ip(ip_address, old_network, new_network):
            return ip_address.replace(old_network, new_network)

        arecords = self.get_current_arecords()
        new_primary_ip = create_new_ip(
            arecords.pop(0), production_network, dr_network) 
        self.replace_records(new_primary_ip)
        if arecords:
            for arec in arecords:
                new_ip = create_new_ip(arec, production_network, dr_network)
                self.add_record(new_ip)

def main(*args):
    """Main function."""
    # Set up logging.
    numeric_level = getattr(logging, loglevel)
    if not isinstance(numeric_level, int):
        raise ValueError("Invalid log level: {}.".format(loglevel))
    
    script_name = os.path.basename(__file__)
    global logger
    logger = logging.getLogger(script_name)
    logfile = "/tmp/{}.log".format(script_name)
    if os.access("/var/log/{}.log".format(script_name), os.W_OK):
        logfile = "/var/log/{}.log".format(script_name)

    fh = logging.FileHandler(logfile)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    fh.setFormatter(formatter)

    logger.addHandler(fh)
    logger.setLevel(numeric_level)

    logger.info("Logger set to %s.", loglevel)

    # Run the thing.
    global keyring
    keyring = dns.tsigkeyring.from_text({ tsigkeyname : tsigkey })

    for hostname in hostnames:
        h = Host(hostname)
        h.validate_current_networks(production_network)
        h.update_all_records()
        # h.check_records() # If this fails, stop processing further hosts.

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main(sys.argv[1:])
