38016 deny tcp from 166.90.150.124 80 to me in
29587 deny tcp from 168.143.119.125 80 to me in
37857 deny tcp from 64.203.14.10 80 to me in
38016 deny tcp from 166.90.150.124 80 to me in
65000 allow ip from any to any
65100 deny tcp from 202.152.30.2 80 to me in
65200 deny tcp from 69.59.149.121 80 to me in
65535 deny ip from any to any
session.MTU = 1500

Current firewall rules:
----------------------
HTTP RESPONSE CODE: 200
r 0.576258 1 257
a 0.576368 257
r 0.576542 257 513
a 0.576560 513
r 0.576655 513 769
r 0.656168 769 1025
r 0.656209 1025 1281
r 0.656240 1281 1537
a 0.656255 1537
r 0.656365 1537 1793
r 0.740100 1793 2049
r 0.740161 2049 2305
r 0.740192 2305 2561
r 0.740222 2561 2817
r 0.740253 2817 3073
r 1.296205 1537 1793
RTO ===> 1.296193 0.740247
Retransmission detected...
RESULT: session.rtt = 0.078136 LastWindow: 6 LIMIT: 2 APPROPRIATE_BYTE_COUNTING
