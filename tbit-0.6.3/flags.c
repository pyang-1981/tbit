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
#include "base.h"
#include "inet.h"
#include "session.h"
#include "capture.h"
#include "support.h"
#include "tbit.h"
#include "history.h"
#include "ecn.h"

extern struct TcpSession session;
extern struct History history[];

static char *FlagsBinVal[] = {
"0000-00", "0000-01", "0000-10", "0000-11", 
"0001-00", "0001-01", "0001-10", "0001-11",
"0010-00", "0010-01", "0010-10", "0010-11",
"0011-00", "0011-01", "0011-10", "0011-11",
"0100-00", "0100-01", "0100-10", "0100-11",
"0101-00", "0101-01", "0101-10", "0101-11",
"0110-00", "0110-01", "0110-10", "0110-11",
"0111-00", "0111-01", "0111-10", "0111-11",
"1000-00", "1000-01", "1000-10", "1000-11", 
"1001-00", "1001-01", "1001-10", "1001-11",
"1010-00", "1010-01", "1010-10", "1010-11",
"1011-00", "1011-01", "1011-10", "1011-11",
"1100-00", "1100-01", "1100-10", "1100-11",
"1101-00", "1101-01", "1101-10", "1101-11",
"1110-00", "1110-01", "1110-10", "1110-11",
"1111-00", "1111-01", "1111-10", "1111-11"};


void FlagsTest (uint32 sourceAddress, uint16 sourcePort, uint32 targetAddress, 
                uint16 targetPort, int mss, uint8 TCPflags) 
{
	int rawSocket;
	struct IPPacket *p;
	struct IPPacket *synPacket;
	char *read_packet;
	struct PacketInfo pi;
	int numTransmits = 0;
	double timeoutTime;
	int IPflag = 1;
	int done = 0;
	uint8 upperfour = (TCPflags&0x3C)>>2; 
	uint8 lowertwo = (TCPflags&0x03)<<6; 

	session.src = sourceAddress;
	session.sport = sourcePort;
	session.dst = targetAddress;
	session.dport = targetPort;
	session.rcv_wnd = 5*mss;
	session.snd_nxt = 0;	
	session.iss = session.snd_nxt;
	session.rcv_nxt = 0;
	session.irs = 0;
	session.mss = mss ;
	session.maxseqseen = 0 ; 
	session.epochTime = GetTime ();
	session.maxpkts = 20; 

	if ((session.dataRcvd = (uint8 *)calloc(sizeof(uint8), mss*session.maxpkts)) == NULL) {
		perror("no memmory to store data:\n");
		Quit(ERR_MEM_ALLOC);
	}

	if ((rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("ERROR: couldn't open socket:");
		Quit(ERR_SOCKET_OPEN);
	}

	if (setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, (char *)&IPflag,sizeof(IPflag)) < 0) {
		perror("ERROR: couldn't set raw socket options:");
		Quit(ERR_SOCKOPT);
	}
	session.socket = rawSocket;
	SetFireWall ();
	
	/* allocate the syn packet - CHANGE*/
	if ((synPacket = (struct IPPacket *)calloc(1, sizeof(struct IPPacket))) == NULL) {
	  perror("ERROR: Could not allocate SYN packet:") ;
	  Quit(ERR_MEM_ALLOC) ; 
	}

	/* Support for IP Options -- New */
	if ((synPacket->ip = (struct IpHeader *)calloc(1, sizeof(struct IpHeader))) == NULL) {
	  perror("ERROR: Could not allocate IP Header for SYN packet:") ;
	  Quit(ERR_MEM_ALLOC) ; 
	}
	
	
	if ((synPacket->tcp = (struct TcpHeader *)calloc(1, sizeof(struct TcpHeader))) == NULL) {
	  perror("ERROR: Could not allocate TCP Header for SYN packet:") ;
	  Quit(ERR_MEM_ALLOC) ; 
	}

	done = 0;
	numTransmits= 0;
	while(!done) {

	  /* fill in and send the SYN packet */
	  WriteIPPacket(synPacket,
			session.src, 
			session.dst,
			session.sport, 
			session.dport,
			session.snd_nxt, 
			session.rcv_nxt, 
			TCPFLAGS_SYN | lowertwo, 
			session.rcv_wnd, 
			0, 
			0, 
			0, 
			0, 
			0,
			upperfour);

	  SendPkt(synPacket, 
		  sizeof(struct IPPacket), 
		  0 /* ip_opt len */, 
		  0 /* tcp_opt len */);
	  session.snd_nxt++;
	  session.rcv_nxt++;
	  numTransmits++; 

	  timeoutTime = GetTime()+2;

	  while((GetTime() < timeoutTime)&&(!done)) {

	    /* Have we captured any packets? */
	    if ((read_packet = (char *)CaptureGetPacket(&pi)) != NULL) {

	      p = (struct IPPacket *)FindHeaderBoundaries(read_packet);

	      /* Received a packet from us to them */
	      if (INSESSION(p, session.src, session.sport, session.dst, session.dport)) {
		continue;
	      }

	      if (INSESSION(p, session.dst, session.dport, session.src, session.sport)) {
		/* Is it a SYN/ACK? */
		if ((p->tcp->tcp_flags & TCPFLAGS_SYN) && /* New */
		    (p->tcp->tcp_flags & TCPFLAGS_ACK) &&  /* New */
		    (ntohl(p->tcp->tcp_ack) == (session.snd_nxt))) {

		  printf ("flags=%s result=SYN/ACK\n", FlagsBinVal[(int)TCPflags]);
		  done = 1; 


		}else {

		  if ((p->tcp->tcp_flags) & (TCPFLAGS_RST)) {
		    printf ("flags=%s result=RST\n", FlagsBinVal[(int)TCPflags]);
		    done = 1; 
		  }

		}
	      }
	    }
	  }

	  if (!done) {
	    if (numTransmits == 3) {
	      printf ("flags=%s result=NO_CONN\n", FlagsBinVal[(int)TCPflags]);
	      done = 1;
	    }
	  }
	}

	free(synPacket->ip);
	free(synPacket->tcp);
	free(synPacket);

	Quit(SUCCESS);

}
