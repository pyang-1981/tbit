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
#include "tbit.h"
#include "history.h"
#include "tahoe_no_fr_check.h"

#define MAXRXMT 20  
#define MAXTO 20  

extern struct TcpSession session;
extern struct History history[];

static uint32 tahoeDrop; 

void TahoeNoFRTest (uint32 sourceIpAddress, uint16 sourcePort, uint32 targetIpAddress, uint16 targetPort, int mss) 
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
		       5, 
		       20, 
		       0, 
		       0) == 0) {
    printf("ERROR: Couldn't establish session\n");
    Quit(NO_SESSION_ESTABLISH);

  }

  SendRequest(session.filename, (void *)TahoeNoFrackData); 
  rcvData (TahoeNoFrackData);

}

void TahoeNoFrackData (struct IPPacket *p) 
{
  uint32 src;
  uint32 dst;
  uint16 sport;
  uint16 dport;
  uint32 seq;
  uint32 ack;
  uint8  flags;
  uint16 win;
  uint16 urp;
  uint16 datalen;
  uint16 ip_optlen;
  uint16 optlen;
  char  *dataptr ;
  int i ; 
  struct IPPacket *ackpkt ; 
  int dropForTahoeNoFrTest = 0 ; 
  
  ReadIPPacket (p, 
		&src, &dst, 
		&sport, &dport, 
		&seq, &ack, &flags, &win,
		&urp, &datalen, 
		&ip_optlen,
		&optlen);

  if (session.debug) {
    printf ("datalen = %d\n\n", (int)datalen);
    if (datalen > 0) {
      dataptr = (char *)p + (int)sizeof(struct IPPacket) + (int)optlen ;		
      for (i = 0 ; i < (int)datalen ; i++) {
	printf ("%c", isprint(dataptr[i])?dataptr[i]:' '); 
      }
    }
    printf("\n====================\n");
  }
  
  if (datalen > session.mss) {
    printf ("ERROR: mss=%d datalen=%d\n", session.mss, datalen);
    Quit(MSS_ERR);
  }
  if ((seq + datalen - session.irs) > session.mss * session.maxpkts) {
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
  
  if(session.maxseqseen <= seq) {
    session.maxseqseen = seq ; 
  }else {
    if (datalen > 0) {
      printf ("##### rexmit packet %f %d %d \n", GetTime()-session.epochTime, seq-session.irs, seq-session.irs+datalen);
      session.totOutofSeq ++ ;
      if ((seq != tahoeDrop) && (session.totOutofSeq < 1)) {
	printf ("ERROR: unwanted packet drop befoer test completion\n");
	Quit(UNWANTED_PKT_DROP); 
      }
    }
  }

  /*
   * drop packet for tahoe test?
   *
   */
  if (session.totDataPktsRcvd == 13) {
    tahoeDrop = seq ;	
    dropForTahoeNoFrTest = 1;
    printf ("##### droppacket %f %d %d\n", GetTime()-session.epochTime, seq-session.irs, seq-session.irs+datalen);
  }
  
  /* from TCP/IP vol. 2, p 808 */
  if (session.debug) {
    printf ("dlen=%d reno=%d seq=%u rcv_nxt=%u rcv_wnd=%u\n", datalen, dropForTahoeNoFrTest, 
	    seq, session.rcv_nxt, session.rcv_wnd);
  }
  if ((datalen > 0) && 
      (dropForTahoeNoFrTest == 0) &&
      (session.rcv_nxt <= seq) && (seq < (session.rcv_nxt+session.rcv_wnd))  &&
      (session.rcv_nxt <= (seq+datalen)) && ((seq+datalen-1) < (session.rcv_nxt + session.rcv_wnd))) {
    int start = seq - session.irs ; 
    int end = start + datalen ; 
    if (session.debug) {
      printf ("rcved = %d-%d\n", start, end);
    }
    for (i = start ; i < end ; i++) {
      session.dataRcvd[i] = 1 ; 
    }
    if (end+session.mss > session.mss*session.maxpkts) {
      if (session.totOutofSeq < 1) {
	Quit(NOT_ENOUGH_PKTS);
      } else {
	TahoeNoFrCheck () ;
	Quit(SUCCESS); 
      }
    }
    start = session.rcv_nxt - session.irs ; 
    end = session.mss*session.maxpkts; 
    for (i = start ; i < end ; i ++) {
      if (session.dataRcvd[i] == 0) {
	break ;
      }
      session.rcv_nxt ++ ;
    }
    if (session.debug) {
      printf ("rcv_nxt = %u\n", (int)session.rcv_nxt);
    }
  }
  
  if (flags & TCPFLAGS_FIN) {
    if (session.debug) {
      printf ("sending fin ack\n");
    }
    if (session.totOutofSeq < 1) {
      Quit(NOT_ENOUGH_PKTS);
    } else {
      TahoeNoFrCheck () ;
      Quit(SUCCESS); 
    }
  }
  else {
    if ((datalen > 0) && (dropForTahoeNoFrTest == 0)) {
      if (session.debug) { 
	printf ("sending ack\n");
      }
      busy_wait(PLOTDIFF);

      /* Allocate space for IP ACK Packet */
      ackpkt = AllocateIPPacket(0, 0, 0, "TahoeNoFR (ACK)");

      SendSessionPacket (ackpkt, 
			 sizeof(struct IpHeader) + sizeof(struct TcpHeader),
			 TCPFLAGS_ACK, 
			 0,
			 0, 
			 0);
      if (session.verbose) {
	printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt-session.irs);
      }
    }
  }
}


void TahoeNoFrCheck () 
{
  int rxmt[MAXRXMT] ; 
  int to[MAXTO] ; 
  int i, j ; 
  int numRxmt = 0, numTO = 0;
  
  /* 
   * lets count retransmissions 
   * using a very dumb algo, but
   * what the heck ....
   * note that the first pkt can not
   * be a retransmission
   */
  
  for (i = 1; i < session.hsz; i++) {
    if ((history[i].type == RCVD) && (history[i].dlen > 0)) {
      for (j = 0 ; j < i-1 ; j++) {
	if ( (history[j].type == RCVD) && (history[j].dlen > 0) &&
	     (history[j].seqno <= history[i].seqno) &&
	     (history[j].nextbyte > history[i].seqno)) {
	  rxmt[numRxmt++] = i ; 
	  if (numRxmt == MAXRXMT) {
	    Quit(TOO_MANY_RXMTS);
	  }
	  break ;
	}
      }
    }
  }
  
  /*
   * lets now count timeouts 
   * just as dumb as before 
   * there can not be a timeout before
   * the first packet
   */
  
  for (i = 1 ; i < session.hsz ; i ++) {
    if ((history[i].type == RCVD) && (history[i].dlen > 0)) {
      int prevDataPkt = -1 ;
      for (j = i-1; j >= 0 ; j --) {
	if ((history[j].type == RCVD) && (history[j].dlen > 0)) {
	  prevDataPkt = j ;	
	  break ;
	}
      }
      if (prevDataPkt > 0) {
	if ((history[i].timestamp - history[prevDataPkt].timestamp)	> RTT_TO_MULT*(session.rtt+PLOTDIFF)) {
	  /* sanity check for rxmt? */
	  /* data pkt after TO must be a retransmission */
	  int j ;
	  int found = 0 ;
	  for (j = 0 ; j < numRxmt ; j++) {
	    if (rxmt[j] == i) {
	      found = 1 ; 
	      break ; 
	    }
	  }
	  if (found == 1) {
	    to[numTO++]	 = i ;
	    if (numTO == MAXTO) {
	      Quit(TOO_MANY_TIMEOUTS);
	    }
	  }
	}
      }
    }
  }
  printf ("#### rx=%d to=%d\n", numRxmt, numTO);
}
