#!/usr/bin/env python3

import sys
import dns.query
import dns.update
import dns.resolver
import dns.tsigkeyring

hosts = [ 'foobar' ]
prod_network = '10.15.0'
dr_network = '10.95.0'

nameserver = '172.16.62.51'

keyring = dns.tsigkeyring.from_text({
    'tappy-bind' : '/lOHWPHv5B6QXKqsEcwWguuIOx+F8jqL1nK92DamiKAChAR60CgD3qI8N0iy2nr+hLIvBVdNcYIyav3JaQYdlg=='
})

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
update = dns.update.Update('laputa.', keyring=keyring, keyalgorithm='hmac-sha512')
update.replace('foobar', 300, 'A', '10.10.10.10')
response = dns.query.tcp(update, nameserver)


# pseud
"""

for each host in hosts:
    check address is in prod network
    save last octet of address
    form new address using last octet
    update with new address

V2 could/should update them all together
"""


