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
#include "support.h"
#include "capture.h"
#include "tbit.h"
#include "history.h"
#include "ini_rto.h"

extern struct TcpSession session;
extern struct History history[];

double synAckRcvd; 
double rxmt[MAXRXMT]; 
int numRxmt = 0;

void IniRTOTest (uint32 sourceIpAddress, uint16 sourcePort, uint32 targetIpAddress, uint16 targetPort, int mss) 
{

  if (EstablishSession(sourceIpAddress,
		       sourcePort,
		       targetIpAddress,
		       targetPort,
		       0,    /* ip_optlen */
		       NULL, /* ip_opt pointer */
		       mss, 
		       0,
		       NULL,
		       4000,
		       10,
		       0,
		       0) == 0) {

    printf("ERROR: Couldn't establish session\nRETURN CODE: %d", NO_SESSION_ESTABLISH);
    Quit(NO_SESSION_ESTABLISH);
  }

  RTOCalc(); 

}

void RTOCalc () {
  
  struct IPPacket *p;
  struct PacketInfo pi;
  char *read_packet;
  double timeoutTime = GetTime() + MAXWAIT;

  synAckRcvd = GetTime();

  while(GetTime() < timeoutTime) {

    if ((read_packet = (char *)CaptureGetPacket(&pi)) != NULL) {

      p = (struct IPPacket *)FindHeaderBoundaries(read_packet);

      if (INSESSION(p, session.dst, session.dport, session.src, session.sport)) {

	if ((p->tcp->tcp_flags == (TCPFLAGS_SYN | TCPFLAGS_ACK)) &&
	    (ntohl(p->tcp->tcp_ack) == session.snd_una)) {
	  
	  rxmt[numRxmt++] = GetTime() - synAckRcvd; 
	  synAckRcvd = GetTime();
	  printf("numRxmt: %d\n", numRxmt);
	  
	  if (session.verbose) {
	    printf ("synack rcvd at time %f\n", synAckRcvd);
	  }
	  
	  if (numRxmt == MAXRXMT) {
	    printResults(MAXRXMT_EXCEED); 
	  }		
	  
	} else {
	  
	  if (p->tcp->tcp_flags & TCPFLAGS_RST) {
	    if (session.verbose) {
	      printf ("rst rcvd at time %f\n", synAckRcvd);
	    }
	    printResults(RST_RCVD);		
	  }
	  
	}
	
      }
    }

    printResults(MAXWAIT_EXCEED);

  }
}

void printResults (int why) 
{
  int i; 
  printf ("#### ");
  switch (why) {
  case MAXRXMT_EXCEED: 
    printf ("Too many retransmits: ");
    break;

  case RST_RCVD: 
    printf ("Termitaed by RST: ");
    break; 

  case MAXWAIT_EXCEED: 
    printf ("Exceeded waiting period: ");
    break;

  default: 
    printf("In correct why value\nRETURN CODE: %d", FAIL);
    Quit(FAIL);
  }

  for (i = 0 ; i < numRxmt; i++) {
    printf ("%.1f ", rxmt[i]);
  }

  if (why == RST_RCVD) {
    printf ("RST at %.1f", GetTime() - synAckRcvd);
  }
  printf ("\n");
  Quit(SUCCESS);

}
