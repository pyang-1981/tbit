09034 deny tcp from 166.90.150.127 80 to me in
04193 deny tcp from 64.202.163.163 80 to me in
09034 deny tcp from 166.90.150.127 80 to me in
39519 deny tcp from 168.143.118.170 80 to me in
65000 allow ip from any to any
65100 deny tcp from 202.152.30.2 80 to me in
65200 deny tcp from 69.59.149.121 80 to me in
65535 deny ip from any to any
session.MTU = 1500

Current firewall rules:
----------------------
HTTP RESPONSE CODE: 200
r 0.728178 1 257
a 0.728288 257
r 0.728458 257 513
a 0.728476 513
r 0.728569 513 769
r 0.808104 769 1025
r 0.808165 1025 1281
r 0.808196 1281 1537
a 0.808213 1537
r 0.808393 1537 1793
r 0.888070 1793 2049
r 0.888130 2049 2305
r 0.888161 2305 2561
r 0.888192 2561 2817
r 0.888222 2817 3073
r 1.437910 1537 1793
RTO ===> 1.437899 0.888216
Retransmission detected...
RESULT: session.rtt = 0.078897 LastWindow: 6 LIMIT: 2 APPROPRIATE_BYTE_COUNTING
