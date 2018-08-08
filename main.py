#!/usr/bin/env python3

import sys
import dns.query
import dns.update
import dns.tsigkeyring

keyring = dns.tsigkeyring.from_text({
    'tappy-bind' : '/lOHWPHv5B6QXKqsEcwWguuIOx+F8jqL1nK92DamiKAChAR60CgD3qI8N0iy2nr+hLIvBVdNcYIyav3JaQYdlg=='
})

update = dns.update.Update('laputa.', keyring=keyring, keyalgorithm='hmac-sha512')
update.add('foobar', 300, 'A', '10.20.30.40')

response = dns.query.tcp(update, '172.16.62.51', timeout=10)
