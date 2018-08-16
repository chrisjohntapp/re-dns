#!/usr/bin/env python3

from sys import argv
from os import path, access, W_OK, chdir
import logging
from dns import tsigkeyring, resolver, update, query

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
production_network = '11.11.11'
dr_network = '12.12.12'
nameserver = '172.16.62.51'
tsigkeyname = 'tappy-bind'
tsigkey = '/lOHWPHv5B6QXKqsEcwWguuIOx+F8jqL1nK92DamiKAChAR60CgD3qI8N0iy2nr+hLIvBVdNcYIyav3JaQYdlg=='
keyalgorithm = 'hmac-sha512'
loglevel = 'DEBUG'
validate_only = False

class Host:
    def __init__(self, hostname):
        """
        Create object representing a single host/hostname.
        """
        self.hostname = hostname
        logger.debug("Created object for hostname {}.".format(self.hostname))

    def get_current_arecords(self):
        """
        Returns list of A records associated with current host.
        """
        oresolver = resolver.Resolver()
        oresolver.nameservers = [ nameserver ]
        logger.debug("Nameserver for {} set to {}.".format(self.hostname, nameserver))
        try:
            response = oresolver.query(
                "{}.{}".format(self.hostname, domain_name), 'A')
        except Exception as e:
            logger.error("Failed to retrieve A records for {}.".format(self.hostname))
            logger.debug(e)
            raise
        arecords = []
        [ arecords.append(resp.address) for resp in response ]
        logger.debug("Query for A records associated with {} returned {}.".format(self.hostname, arecords))
        return arecords

    def get_current_networks(self, arecords='default'):
        """
        Returns a list of the 3-octet class C networks of the current host's A records.
        Takes a list of A records or, if not provided, determines the list itself.
        """
        if arecords == 'default':
            arecords = self.get_current_arecords()
        networks = []
        # Remove the last octet of address(es).
        [ networks.append('.'.join(arec.split('.')[-4:-1])) for arec in arecords ]
        logger.debug("get_current_networks derived {} from {}.".format(networks, arecords))
        return networks

    def validate_current_networks(self, category):
        """
        All A records associated with a host should be on the production network for the current
        DR plan to succeed. This function checks that this is true, and aborts if false. Useful for
        testing readiness for DR but should not be used in production, as it would mean that a
        single misconfigured host would cause DR to fail.
        """
        def check_category(networks, category):
            all(x == category for x in networks)

        networks = self.get_current_networks()
        try:
            check_category(networks, category)
        except:
            logger.error("Not all A records associated with {} are in the expected network {}.".format(self.hostname, production_network))
            raise SystemExit
        logger.debug("All A records associated with {} are in the expected network.".format(self.hostname))

    def replace_records(self, new_ip, ttl=300):
        """
        Replace all existing A records with a single new one.
        """
        oupdate = update.Update(
            domain_name, keyring=keyring, keyalgorithm=keyalgorithm)
        oupdate.replace(self.hostname, ttl, 'A', new_ip)
        try:
            query.tcp(oupdate, nameserver)
        except Exception as e:
            logger.error("Attempt to replace A records for {} failed.".format(self.hostname))
            logger.debug(e)
            raise SystemExit
        logger.info("All A records for {} replaced with {}.".format(self.hostname, new_ip))
 
    def add_record(self, new_ip, ttl=300):
        """
        Add A records to an existing one.
        """
        oupdate = update.Update(
            domain_name, keyring=keyring, keyalgorithm=keyalgorithm)
        oupdate.add(self.hostname, ttl, 'A', new_ip)
        try:
            query.tcp(oupdate, nameserver)
        except Exception as e:
            logger.error("Attempt to add A record {} to {} failed.".format(new_ip, self.hostname))
            logger.debug(e)
            raise
        logger.info("A record {} added to {}.".format(new_ip, self.hostname))

    def update_all_records(self):
        """
        Updates all A records for host with versions in DR network.
        """
        def create_new_ip(ip_address, old_network, new_network):
            return ip_address.replace(old_network, new_network)

        arecords = self.get_current_arecords()
        new_primary_ip = create_new_ip(arecords.pop(0), production_network, dr_network)
        self.replace_records(new_primary_ip)
        if arecords:
            for arec in arecords:
                new_ip = create_new_ip(arec, production_network, dr_network)
                self.add_record(new_ip)

def main(*args):
    """
    Main function.
    """
    # Set up logging.
    numeric_level = getattr(logging, loglevel)
    if not isinstance(numeric_level, int):
        raise ValueError("Invalid log level: {}.".format(loglevel))
    script_name = path.basename(__file__)
    global logger
    logger = logging.getLogger(script_name)

    logfile = "/tmp/{}.log".format(script_name)
    if access("/var/log/{}.log".format(script_name), W_OK):
        logfile = "/var/log/{}.log".format(script_name)
    fh = logging.FileHandler(logfile)

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    fh.setFormatter(formatter)

    logger.addHandler(fh)
    logger.setLevel(numeric_level)
    logger.info("Logger set to {}.".format(loglevel))

    # Run the thing.
    global keyring
    keyring = tsigkeyring.from_text({ tsigkeyname : tsigkey })

    for hostname in hostnames:
        h = Host(hostname)
        if validate_only:
            h.validate_current_networks(production_network)
        else:
            h.update_all_records()

if __name__ == '__main__':
    chdir(path.dirname(path.abspath(__file__)))
    main(argv[1:])
