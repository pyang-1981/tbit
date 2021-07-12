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
#include "timewait.h"

extern struct TcpSession session;
extern struct History history[];
static int finAckd = 0; 
double finAckdTime; 

void TimeWaitTest (uint32 sourceIpAddress, uint16 sourcePort, uint32 targetIpAddress, uint16 targetPort, int mss) 
{
  int optlen; 
  char *opt; 

  optlen = 4 ;
  if ((opt=(char *)calloc(sizeof(uint8), optlen)) == NULL)	{
    perror("ERROR: Could not allocate opt:");
    Quit(ERR_MEM_ALLOC);
  }

  /* mss option */
  opt[0] = (uint8)TCPOPT_MAXSEG ; 
  opt[1] = (uint8)TCPOLEN_MAXSEG ; 
  *((uint16 *)((char *)opt+2)) = htons(mss);
	
  if (EstablishSession(sourceIpAddress,
		       sourcePort,
		       targetIpAddress,
		       targetPort,
		       0,    /* ip_opt len */
		       NULL, /* ip_opt pointer */ 
		       mss,
		       optlen,
		       opt,
		       8000/mss,
		       1000,
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\n");
    Quit(NO_SESSION_ESTABLISH);
  }

  SendRequest(session.filename, (void *)TimeWaitAckData); 
  rcvData (TimeWaitAckData);

}

void TimeWaitAckData (struct IPPacket *p) 
{
  
  uint32 seq = history[session.hsz - 1].seqno;
  uint16 datalen = history[session.hsz - 1].dlen;
  int fin = history[session.hsz - 1].fin; 
  int i;
  struct IPPacket *ackpkt;
  
  if (session.debug) {
    printf ("datalen = %d\n\n", (int)datalen);
  }
  if (datalen > session.mss) {
    printf ("ERROR: mss=%d datalen=%d\n", session.mss, datalen);
    Quit(MSS_ERR);
  }
  if ((seq+datalen-session.irs) > session.mss*session.maxpkts) {
    printf ("ERROR: buffer overflow: %u %d %u %d %d\n", 
	    seq, datalen, session.irs, seq+datalen-session.irs, session.mss*session.maxpkts);
    Quit(BUFFER_OVERFLOW); 
  }
  if (datalen > 0) {
    session.totDataPktsRcvd ++ ;
    if (session.verbose) {
      printf ("r %f %d %d\n", GetTime() - session.epochTime, seq-session.irs, seq-session.irs+datalen);
    }
  }
  if(session.maxseqseen < seq+datalen-1) {
    session.maxseqseen = seq +datalen-1; 
  }
  /* from TCP/IP vol. 2, p 808 */
  if ((!finAckd) &&
      (session.rcv_nxt <= seq) && (seq < (session.rcv_nxt+session.rcv_wnd))  &&
      (session.rcv_nxt <= (seq+datalen)) && ((seq+datalen-1) < (session.rcv_nxt + session.rcv_wnd))) {
    /* 
     * we don't want to deal with FINs that may arrive while there is still
     * some data pending. 
     */
    int start, end; 
    if (seq == session.rcv_nxt) {
      start = seq - session.irs ; 
      end = start + datalen ; 
      if (session.debug) {
	printf ("rcved = %d-%d\n", start, end);
      }
      for (i = start ; i < end ; i++) {
	session.dataRcvd[i] = 1 ; 
      }
    }
    start = session.rcv_nxt - session.irs ; 
    end = session.mss*session.maxpkts ; 
    for (i = start ; i < end ; i ++) {
      if (session.dataRcvd[i] == 0) {
	break ;
      }
      session.rcv_nxt ++ ;
    }
  }
  if (!finAckd) {

    busy_wait(PLOTDIFF);
    if (session.verbose) {
      printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt-session.irs);
    }

    /* Allocate space for IP ACK Packet */
    ackpkt = AllocateIPPacket(0, 0, 0, "TimeWait (ACK)");
    SendSessionPacket (ackpkt, 
		       sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		       TCPFLAGS_ACK, 
		       0,
		       0, 
		       0);
    if (fin) {

      if (session.rcv_nxt == session.maxseqseen + 1) { 

	session.rcv_nxt++;
	if (session.verbose) {
	  printf ("#### sending fin ack\n");
	  printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt-session.irs);
	}


	SendSessionPacket (ackpkt, 
			   sizeof(struct IpHeader) + sizeof(struct TcpHeader),
			   TCPFLAGS_FIN | TCPFLAGS_ACK, 
			   0,
			   0, 
			   0);
	finAckd = 1;

      }
    }

  }else {
    finAckdTime = GetTime ();
    attemptConnection ();
  }
}

void attemptConnection ()
{
  struct IPPacket *p;
  struct IPPacket *synPacket;
  char *read_packet;
  struct PacketInfo pi;
  int numRetransmits = 0;
  double timeoutTime;

  /*send SYN, and wait for SYN/ACK */
  session.iss = session.snd_nxt - 5;
  session.snd_nxt = session.iss;
  session.snd_una = session.snd_nxt;
  session.rcv_nxt = 0;
  session.irs = 0;
  timeoutTime = GetTime();

  while(numRetransmits < SYN_ATTEMPTS) {

    while(GetTime() < timeoutTime) {

      /* Have we captured any packets? */

      if ((read_packet = (char *)CaptureGetPacket(&pi)) != NULL) {

	p = (struct IPPacket *)FindHeaderBoundaries(read_packet);

	/* Received a packet from us to them */
	if (INSESSION(p, session.src, session.sport, session.dst, session.dport)) {
	  /* Is it a SYN? */
	  if (p->tcp->tcp_flags == TCPFLAGS_SYN) {
	    if (session.debug) {
	      PrintTcpPacket(p); 
	    }
	    StorePacket(p);
	    session.totSeenSent ++ ;
	  }
	  continue;
	}
	if (INSESSION(p, session.dst, session.dport, session.src, session.sport)) {
	  /* Is it a SYN/ACK? */
	  if ( (p->tcp->tcp_flags == (TCPFLAGS_SYN | TCPFLAGS_ACK)) &&
	       (ntohl(p->tcp->tcp_ack) == session.snd_una + 1)) {
	    timeoutTime = GetTime(); /* force exit */
	    if (session.debug) {
	      PrintTcpPacket(p);
	    }
	    printf ("#### %f < time wait < %f\n", GetTime()-finAckdTime-SYNTIMEOUT, GetTime()-finAckdTime);
	    Quit(SUCCESS);
	  }
	}

      }
    }
    printf("SYN timeout. Retransmitting: %d\n", ++numRetransmits);
    
    synPacket = AllocateIPPacket(0, 0, 0, "TimeWait (SYN)");

    SendSessionPacket(synPacket, 
		      //sizeof(struct IPPacket), 
		      sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		      TCPFLAGS_SYN, 
		      0,
		      0, 
		      0);

    timeoutTime = GetTime() + SYNTIMEOUT;

  }

  printf ("#### No connection after %d atttempts in %f seconds\n", numRetransmits, GetTime()-finAckdTime);
  Quit(FAIL);

}
