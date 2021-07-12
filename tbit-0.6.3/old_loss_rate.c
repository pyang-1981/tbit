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
#include "loss_rate.h"

#define MAXTO 1000000
#define MAXRXMT 1000000

extern struct TcpSession session;
extern struct History history[];

void LossRateTest (uint32 sourceIpAddress, uint16 sourcePort, uint32 targetIpAddress, uint16 targetPort, int mss) 
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
		       100000,
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\n");
    Quit(NO_SESSION_ESTABLISH);
  }

  SendRequest(session.filename, (void *)LossRateAckData); 
  rcvData(LossRateAckData);

}

void LossRateAckData (struct IPPacket *p) 
{
  uint32 seq = history[session.hsz-1].seqno;
  uint16 datalen = history[session.hsz-1].dlen;
  int fin = history[session.hsz-1].fin; 
  int i, j, numTO = 0;
  int numRxmt = 0;
  struct Rxmt rxmt[MAXRXMT];
  struct IPPacket ackpkt ;

  int to[MAXTO] ; 

  //PrintTcpPacket(p);
  if (datalen > session.mss) {
    printf ("ERROR: mss=%d datalen=%d\n", session.mss, datalen);
    Quit(MSS_ERR);
  }

  if (fin) {

    printf("Totdata = %d\n", session.rcv_nxt - session.irs);
    printf("session.rtt = %f\n", session.rtt);

    // Count the number of retransmissions
    printf("Counting number of retransmissions...\n");
    for (i = 1; i < session.hsz; i++) {

      if ((history[i].type == RCVD) && (history[i].dlen > 0)) {

	for (j = 0 ; j < i - 1 ; j++) {
	  if ((history[j].type == RCVD) && (history[j].dlen > 0) &&
	      (history[j].seqno <= history[i].seqno) &&
	      (history[j].nextbyte > history[i].seqno)) {

	    rxmt[numRxmt].pkt_num = history[i].pkt_num;
	    rxmt[numRxmt].hist_index = i;

	    numRxmt++;
	    break ;
	  }
	}
      }
    }
    printf("numRxmt: %d\n", numRxmt);

    // Count the number and values of the RTO
    printf("Counting number of timeouts...\n");
    for (i = 1 ; i < session.hsz ; i ++) {

      if ((history[i].type == RCVD) && (history[i].dlen > 0)) {

	int prevDataPkt = -1 ;
	for (j = i - 1; j >= 0; j--) {
	  if ((history[j].type == RCVD) && (history[j].dlen > 0)) {
	    prevDataPkt = j ;	
	    break;
	  }
	}
	if (prevDataPkt > 0) {
	  
	  if ((history[i].timestamp - history[prevDataPkt].timestamp) > RTT_TO_MULT * (session.rtt + PLOTDIFF)) {
	  
	    /* sanity check for rxmt? */
	    /* data pkt after TO must be a retransmission */
	    int j ;
	    int found = 0 ;
	    
	    for (j = 0 ; j < numRxmt ; j++) {

	      if (rxmt[j].hist_index == i) {

		found = 1 ; 

		if (session.verbose) {
		  printf ("#### timeout: prev=%d prevtime=%f this=%d thistime=%f timediff=%f thresh=%f\n", 
			  history[prevDataPkt].seqno - session.irs, history[prevDataPkt].timestamp, 
			  history[i].seqno - session.irs, history[i].timestamp, 
			  (history[i].timestamp - history[prevDataPkt].timestamp), 
			  RTT_TO_MULT * (session.rtt + PLOTDIFF));
		}
		break ; 
	      }
	    }
	    
	    if (found == 1) {
	      to[numTO++] = i ;
	    }
	  } 
	}
      }
    }
    printf("numTO: %d\n", numTO);
    Quit(SUCCESS); 
  }
  
  // Flip a coin and with probability loss-prob drop the packet


  if (datalen > 0) {
    session.totDataPktsRcvd++ ;
    if (session.verbose) {
      printf ("r %f %d %d\n", GetTime() - session.epochTime, seq-session.irs, seq-session.irs+datalen);
    }
  }
  if(session.maxseqseen < seq+datalen-1) {
    session.maxseqseen = seq +datalen-1; 
  }
  /* from TCP/IP vol. 2, p 808 */
  if ((session.rcv_nxt <= seq) && (seq < (session.rcv_nxt+session.rcv_wnd))  &&
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
    end = session.mss * session.maxpkts ; 
    for (i = start ; i < end ; i ++) {
      if (session.dataRcvd[i] == 0) {
	break ;
      }
      session.rcv_nxt++ ;
    }
  }
  if (session.verbose) {
    printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt-session.irs);
  }
  SendSessionPacket (&ackpkt, 
		     sizeof(struct IPPacket), 
		     TCPFLAGS_ACK, 
		     0, /* ip options length */
		     0, /* tcp options length */
		     0);

}
