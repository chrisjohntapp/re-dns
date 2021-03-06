#!/usr/bin/env python3

# This script should be run as part of the disaster recovery process. Point it
# to an authoritative nameserver which is configured to accept dynamic updates
# from the configured tsig key, and it will replace all A records in the
# PRIMARY_NETWORK with A records in the DR_NETWORK, for the hosts listed in
# HOSTNAMES. The last octet of the IP address remains the same.
# Hosts may have multiple A records; the script will update all of them.

# The script makes the following assumptions:
# * All networks are class C.
# * All hostnames exist under same domain name.
# * Hosts only need A records updated.
# * Hosts are not multi-homed (If they are, only the IPs on PRIMARY_NETWORK will
#   be updated).

from sys import argv
from os import path, access, W_OK, chdir, environ
import logging
from dns import tsigkeyring, resolver, update, query
from json import loads


#===============================================================================
# Configurables.
# Set here and/or override with environment variables.
#===============================================================================

# Failover (to DR site) or Failback?
ACTION = environ.get('ACTION', 'Failover')

# Auth nameserver for the zone.
NAMESERVER = environ.get('NAMESERVER', '172.16.62.51')

# List of hostnames the script will operate on.
if 'HOSTNAMES' in environ:
    HOSTNAMES = loads(environ['HOSTNAMES'])
else:
    HOSTNAMES = [
        'foobar',
        'barfoo'
    ]

# All hosts must use the same domain name.
DOMAIN_NAME = environ.get('DOMAIN_NAME', 'laputa')

# Specify primary network and network at the DR site.
PRIMARY_NETWORK = environ.get('PRIMARY_NETWORK', '10.16.14')
DR_NETWORK = environ.get('DR_NETWORK', '192.168.12')

# Zone must be configured to allow-update using this key.
TSIGKEYNAME = environ.get('TSIGKEYNAME', 'tappy-bind')
TSIGKEY = environ.get(
    'TSIGKEY', '/lOHWPHv5B6QXKqsEcwWguuIOx+F8jqL1nK92DamiKAChAR60CgD3qI8N0iy2nr+hLIvBVdNcYIyav3JaQYdlg==')
KEYALGORITHM = environ.get('KEYALGORITHM', 'hmac-sha512')

# Misc.
LOGLEVEL = environ.get('LOGLEVEL', 'DEBUG')
VALIDATE = environ.get('VALIDATE', False) # For testing only.
VALIDATE_TARGET = environ.get('VALIDATE_TARGET', 'Primary') # Or 'DR'.


#===============================================================================
# Classes.
#===============================================================================

class Host:
    def __init__(self, hostname):
        """
        Create instance representing a single host.
        """
        self.hostname = hostname
        logger.info(
            "Created host instance for hostname {}.".format(self.hostname)
        )

    def get_current_a_records(self):
        """
        Queries configured nameserver for A records associated with current host
        instance. Returns a list of IP addresses.
        """
        o_resolver = resolver.Resolver()
        o_resolver.nameservers = [ NAMESERVER ]
        logger.info(
            "Nameserver for {} set to {}.".format(self.hostname, NAMESERVER)
        )

        try:
            response = o_resolver.query(
                "{}.{}".format(self.hostname, DOMAIN_NAME), 'A')
            logger.debug(response)
        except Exception as e:
            logger.error(
                "Failed to retrieve A records for {}.".format(self.hostname)
            )
            logger.debug(e)
            raise

        a_records = []
        [ a_records.append(resp.address) for resp in response ]
        logger.info(
            "Query for A records associated with {} returned {}.".format(
                self.hostname, a_records
            )
        )
        return a_records

    def get_current_networks(self, a_records='default'):
        """
        Returns a list of the 3-octet class C networks of a list of A records.
        Takes a list of A records or, if not provided, uses the current host
        object's A records.
        """
        if a_records == 'default':
            a_records = self.get_current_a_records()

        # Remove the last octet of address(es).
        networks = []
        [ networks.append(
            '.'.join(rec.split('.')[-4:-1])
        ) for rec in a_records ]
        logger.info(
            "Derived networks {} from addresses {}.".format(networks, a_records)
        )
        return networks

    def validate_current_networks(self, category):
        """
        All A records associated with a host should be on the primary network
        for the current DR plan to succeed. This function checks that this is
        true, and aborts if false. Useful for testing readiness for DR but
        should not be used in production, as it would mean that a single
        misconfigured host would cause DR to fail.
        """
        def check_category(networks, category):
            """
            Return True if all networks match category, or False otherwise.
            """
            all(x == category for x in networks)

        networks = self.get_current_networks()
        try:
            check_category(networks, category)
        except:
            logger.error(
                "Not all A records associated with {} are in the expected \
                network {}.".format(self.hostname, PRIMARY_NETWORK)
            )
            raise SystemExit
        logger.info(
            "All A records associated with {} are in the expected \
            network.".format(self.hostname))

    def replace_records(self, new_ip, ttl=300):
        """
        Replaces all existing A records for the current instance with a single
        new one.
        """
        o_update = update.Update(
            DOMAIN_NAME, keyring=KEYRING, keyalgorithm=KEYALGORITHM)
        o_update.replace(self.hostname, ttl, 'A', new_ip)

        try:
            query.tcp(o_update, NAMESERVER)
        except Exception as e:
            logger.error(
                "Attempt to replace A records for {} failed.".format(
                    self.hostname
                )
            )
            logger.debug(e)
            raise SystemExit
        logger.info(
            "All A records for {} replaced with {}.".format(
                self.hostname, new_ip
            )
        )
 
    def add_record(self, new_ip, ttl=300):
        """
        Adds an A record for the current instance.
        """
        o_update = update.Update(
            DOMAIN_NAME, keyring=KEYRING, keyalgorithm=KEYALGORITHM)
        o_update.add(self.hostname, ttl, 'A', new_ip)

        try:
            query.tcp(o_update, NAMESERVER)
        except Exception as e:
            logger.error(
                "Attempt to add A record {} to {} failed.".format(
                    new_ip, self.hostname
                )
            )
            logger.debug(e)
            raise
        logger.info("A record {} added to {}.".format(new_ip, self.hostname))

    def update_all_records(self):
        """
        Updates all A records for current instance with DR network versions.
        """
        def create_new_ip(ip_address, old_network, new_network):
            """
            Changes the network portion (class C only) of an IP address from
            old_network to new_network, and returns the result.
            """
            return ip_address.replace(old_network, new_network)

        a_records = self.get_current_a_records()

        # Set Failover or Failback.
        if ACTION == 'Failover':
            net_a = PRIMARY_NETWORK
            net_b = DR_NETWORK
        elif ACTION == 'Failback':
            net_a = DR_NETWORK
            net_b = PRIMARY_NETWORK
        else:
            logger.error("Unrecognised ACTION.")
            raise SystemExit

        # Replace all current records with a single new record.
        new_primary_ip = create_new_ip(
            a_records.pop(0), net_a, net_b)
        self.replace_records(new_primary_ip)

        # If the instance has additional IP addresses, add records for these.
        if a_records:
            for rec in a_records:
                new_ip = create_new_ip(rec, net_a, net_b)
                self.add_record(new_ip)


#===============================================================================
# Module Functions.
#===============================================================================

def main(*args):
    """
    Main function.
    """
    # Set up logging.
    numeric_level = getattr(logging, LOGLEVEL)
    if not isinstance(numeric_level, int):
        raise ValueError("Invalid log level: {}.".format(LOGLEVEL))
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
    logger.info("Logger set to {}.".format(LOGLEVEL))

    # Set constants.
    global KEYRING
    KEYRING = tsigkeyring.from_text({ TSIGKEYNAME : TSIGKEY })

    # Run the thing.
    for hostname in HOSTNAMES:
        h = Host(hostname)
        if VALIDATE:
            if VALIDATE_TARGET == 'Primary':
                target = PRIMARY_NETWORK
            elif VALIDATE_TARGET == 'DR':
                target = DR_NETWORK
            else:
                logger.error("VALIDATE_TARGET not recognised.")
                raise SystemExit
            h.validate_current_networks(target)
        else:
            h.update_all_records()


#===============================================================================
# Run.
#===============================================================================

if __name__ == '__main__':
    chdir(path.dirname(path.abspath(__file__)))
    main(argv[1:])
