30854 deny tcp from 166.90.150.115 80 to me in
18085 deny tcp from 168.143.154.34 80 to me in
18462 deny tcp from 64.209.232.250 80 to me in
30854 deny tcp from 166.90.150.115 80 to me in
65000 allow ip from any to any
65100 deny tcp from 202.152.30.2 80 to me in
65200 deny tcp from 69.59.149.121 80 to me in
65535 deny ip from any to any
session.MTU = 1500

Current firewall rules:
----------------------
HTTP RESPONSE CODE: 200
r 1.253068 1 257
a 1.253176 257
r 1.253348 257 513
a 1.253367 513
r 1.253462 513 769
r 1.332995 769 1025
r 1.333035 1025 1281
r 1.333066 1281 1537
a 1.333082 1537
r 1.333189 1537 1793
r 1.413024 1793 2049
r 1.413087 2049 2305
r 1.413118 2305 2561
r 1.413149 2561 2817
r 1.413180 2817 3073
r 1.964910 1537 1793
RTO ===> 1.964900 1.413173
Retransmission detected...
RESULT: session.rtt = 0.078131 LastWindow: 6 LIMIT: 2 APPROPRIATE_BYTE_COUNTING
