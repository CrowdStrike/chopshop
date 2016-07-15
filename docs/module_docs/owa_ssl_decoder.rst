# OWA Traffic Parser ChopShop module

The Outlook Web Application traffic parser will take a PCAP with OWA session data to extract 

* Username and Password
* Emails Accessed (timestamp, subject, senders, recipients)
* Emails Searched (timestamp, subject)

Parsing Outlook Web Application session traffic can provide valuable information if an attacker has compromised an OWA server and using stolen credentials to access emails.  


```
owa_ssl_decoder (0.1) -- requires ChopLib 4.0 or greater:
Parse OWA activity from PCAP. Requires 'chop_ssl' and http' parent module.
Usage: ./chopshop -f owa_activity.pcap "chop_ssl -k ssl_keys/email_server.key|http|owa_ssl_decoder" 

Options:
  -h, --help           show this help message and exit
```

## Installion instructions 
* Grab and Set up MITRE's ChopShop network decoder framework from https://github.com/MITRECND/chopshop
* Chopshop's HTTP module requires Python library htpy, you can grab it on MITRE's Github https://github.com/MITRECND/htpy 
* Installing modules are simple, just copy over the ChopShop module `owa_ssl_decoder.py` file to ChopShop's modules directory. 

* Since OWA sessions are over SSL, you will need the private key of the OWA serer in RSA format to decode the traffic. 


* Private Key should be in RSA format eg.:
```
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCt7k7fAoX2xvmRIDndTUXZXtKQJxjsFlPJgUDyD577rn4zfhcg
LYKnzyfv+yp1XkN9avaZ8ih4Ug8oSsU4aopVweqLYqvvD1ZJq+7r2xxME10S2rMn
kRvdjWGQ+4EDFSmobtsqWVfsNAi5E0ZpyQEJO485oMqTDxSco0mzgUGwUwIDAQAB
AoGAUaM+f+xmRruEHns6zcXcWDfqq2C+kOm18Cnr+vIcFFQFxlOTtTXHUs6oFzsT
5b0V/oM7Nmz0U+1oUegug9l2Dh5kIc59l2kXwAZba9PRgck+E+ub61Hj91QhMLd9
BKmJnJqdP78Xam7qRhn3lkEfzGXmsAfh2VZ5tK/Cd8U5xfkCQQDZwy+CmFk6aubM
J+qxUhMibE0WPuDF0/plf/D5/ko4/mX7MiISACdWoxWDCWzvcU43ru1KxY8IdnkK
3Nh6SwGnAkEAzHjQsG/QIayNbL5sPCmhuFeZwPXQBVWTWEdy4Ixqj1X+N0rFlN8R
QHV7+x1nKy92hpWXErxC0HkULcQq/355dQJAA8BaDCzltJzs1u2FHILmc3xcI5r3
slDBiogWtafMzYiMZzRo49h+1P5AO56o8sMH7uujiNs4aJPp5+cAD7NFFwJBAMXd
9DWJPmQX0xP0glEGCJWXUBbGyXMgCOJY4fYia8whb0yacvFJnCxAhKXRIlFMMOq0
P+nFfPK4+KoBN4rfHTECQQC5H3vc/SeWj8Q7WBO/R83u4wpiAb15/Pii3ponQP1S
R1o8ZiQSDB6T8xWPx2M+EV4QNW7jBVVtzV024dJZa3AO
-----END RSA PRIVATE KEY-----
```
*Copy Private key into a text file eg. 'email_server.key'

## Usage Examples:

Parse OWA session PCAP 'owa_activity.pcap', using email_server.key 
```
./chopshop -f owa_activity.pcap "chop_ssl -k ssl_keys/email_server.key|http|owa_ssl_decoder" 
```


* Sample Output:

```
sansforensics@siftworkstation:~/Desktop/chopshop$ ./chopshop -f owa_activity.pcap "chop_ssl -k ssl_keys/email_server.key|http|owa_ssl_decoder" 
Starting ChopShop (Created by MITRE)
Initializing Modules ...
  Initializing module 'chop_ssl'
  Initializing module 'http'
  Initializing module 'owa_ssl_decoder'
Running Modules ...
-----OWA Server and Account-----
Server: https://email.acmeinc.com/owa/
User: acmeinc\bbunny Password: c@rr0t$
--------Accessed Email----------
53.94.17.73:55373 --> 172.21.1.150:443
Packet Timestamp: 2016-04-26 07:53:06 UTC
Email Timestamp: Tuesday, April 26, 2016 3:50 AM
Subject: Proposal for new birdhouse
From: Tweety Bird, Tweety<tbird@acmeinc.com>
To: Bugs Bunny, Bugs<bbunny@acmeinc.com>
--------Accessed Email----------
53.94.17.73:55380 --> 172.21.1.150:443
Packet Timestamp: 2016-04-26 07:53:14 UTC
Email Timestamp: Tuesday, April 26, 2016 3:50 AM
Subject: Update on recent cat problem.
From: Tweety Bird, Tweety<tbird@acmeinc.com>
To: Bugs Bunny, Bugs<bbunny@acmeinc.com>
--------Searched Email Subjects----------
53.94.17.73:55378 --> 172.21.1.150:443
Packet Timestamp: 2016-04-26 07:55:00 UTC
New Security System  
Service Announcement
My new BFF
```

## Author
```
William Tan
william.tan@crowdstrike.com
```

## References
* https://github.com/MITRECND/chopshop
* https://github.com/MITRECND/htpy
* http://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/decrypting-ssl-with-chopshop
