
/*
 Copyright (c) 2000  
 International Computer Science Institute
 All rights reserved.

 This file may contain software code originally developed for the
 Sting project. The Sting software carries the following copyright:

 Copyright (c) 1998, 1999
 Stefan Savage and the University of Washington.
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. All advertising materials mentioning features or use of this software
    must display the following acknowledgment:
      This product includes software developed by ACIRI, the AT&T
      Center for Internet Research at ICSI (the International Computer
      Science Institute). This product may also include software developed
      by Stefan Savage at the University of Washington.  
 4. The names of ACIRI, ICSI, Stefan Savage and University of Washington
    may not be used to endorse or promote products derived from this software
    without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY ICSI AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL ICSI OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.
*/

#define MAXRESETRETRANSMITS (3)
/*#define INSESSION(p, src, sport, dst, dport)			\
		(((p)->ip.ip_src == (src)) && ((p)->ip.ip_dst == (dst)) &&	\
		 ((p)->ip.ip_p == IPPROTOCOL_TCP) &&			\
		 ((p)->tcp.tcp_sport == htons(sport)) &&			\
		 ((p)->tcp.tcp_dport == htons(dport)))*/

#define INSESSION(p, src, sport, dst, dport)			\
		(((p)->ip->ip_src == (src)) && ((p)->ip->ip_dst == (dst)) &&	\
		 ((p)->ip->ip_p == IPPROTOCOL_TCP) &&			\
		 ((p)->tcp->tcp_sport == htons(sport)) &&			\
		 ((p)->tcp->tcp_dport == htons(dport)))

#ifdef __FreeBSD__
extern struct ip_fw firewallRule;
extern struct ip_fw dummynetFirewallRule;  // AM: For defining a dummynet pipe
#endif /* __FreeBSD__ */
#ifdef linux
extern struct ip_fwchange firewallRule;
#endif /* linux */

void SetFireWall () ;
void SendReset(); 
RETSIGTYPE SigHandle (int signo);
void Cleanup(); 
void Quit(int how);
double GetTime(); 
double GetTimeMicroSeconds(); 
void PrintTimeStamp(struct timeval *ts); 
void processBadPacket (struct IPPacket *p);
void busy_wait(double wait);
void ResetLroGro();
