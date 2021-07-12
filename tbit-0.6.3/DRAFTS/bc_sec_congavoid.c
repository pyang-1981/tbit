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
#include <math.h>
#include "base.h"
#include "inet.h"
#include "session.h"
#include "support.h"
#include "capture.h"
#include "tbit.h"
#include "history.h"
#include "bc_sec_congavoid.h"

extern struct TcpSession session;
extern struct History history[];

void BCSecCongAvoidTest(uint32 sourceIpAddress, uint16 sourcePort, \
		      uint32 targetIpAddress, uint16 targetPort, int mss)
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
  
  session.bytecounting_type = SECURITY_MODE_CONGAVOID;
  session.ack_rate = 1;
  session.ack_bytes = session.mss;
  printf("BYTECOUNTING TEST TYPE: %d ack_bytes: %d ack_rate: %d\n", 
	 session.bytecounting_type, session.ack_bytes, session.ack_rate);

  SendRequest(session.filename, (void *)BCSecCongAvoidAckData); 
  rcvData(BCSecCongAvoidAckData);

}

void BCSecCongAvoidAckData(struct IPPacket *p) 
{

  uint32 seq = history[session.hsz-1].seqno;
  uint32 last_rcv_nxt;
  uint16 datalen = history[session.hsz-1].dlen;
  int fin = history[session.hsz - 1].fin; 
  int i;
  int num_acks;
  struct IPPacket ackpkt ;
  static int seen_datalen = 0;
  static int pkts_rcvd_no_ack_snt = 0;
  static int acks = 0;
  static int pkts = 0;

  if (session.debug) {
    printf("In BCSecCongAvoidAckData...\n");
  }

  if (seen_datalen < datalen) {
    seen_datalen = datalen;
  }

  if (datalen > session.mss) {
    printf ("ERROR: mss=%d datalen=%d\n", session.mss, datalen);
    Quit(MSS_ERR);
  }

  //if (fin || ((seq + datalen - session.irs) > session.mss * session.maxpkts)) {
  if (fin) {
    int i;
    printf("mss = %d Totdata = %d\n", seen_datalen, session.rcv_nxt - session.irs);
    printf("session.rtt = %f\n", session.rtt);

    printf("history size: %d, session.irs: %u\n", session.hsz, session.irs);
    for (i = 0; i < session.hsz; i++) {
      if (history[i].type == RCVD) {
	printf("R - session.rtt: %f, pktno: %d, pkt.arrtime: %f, pkt.seqno: %u, pkt.ackno: %u\n", 
	       session.rtt, 
	       i, 
	       history[i].timestamp,
	       history[i].seqno/* - session.irs*/,
	       history[i].ackno);
      }
      if (history[i].type == SENT) {
	printf("S - session.rtt: %f, pktno: %d, pkt.arrtime: %f, pkt.seqno: %u, pkt.ackno: %u\n", 
	       session.rtt, 
	       i, 
	       history[i].timestamp,
	       history[i].seqno,
	       history[i].ackno/* - session.irs*/);
      }


    }
    printf("TOTAL PKTS: %d, TOTALS ACKS: %d\n", pkts, acks);
    Quit(SUCCESS); 
  }

  if (datalen > 0) {
    session.totDataPktsRcvd++;
    pkts++;
    if (session.verbose) {
      printf ("r %f %d %d\n", GetTime() - session.epochTime, seq-session.irs, seq-session.irs+datalen);
    }
  }

  if(session.maxseqseen < seq+datalen-1) {
    session.maxseqseen = seq + datalen-1; 
  }

  /* from TCP/IP vol. 2, p 808 */
  /* Test: 
     1. The next byte to be rcvd should be less or equal than seq
     (seq = first byte in the rcvd data segment) AND
     2. The first byte in the rcvd data segment must be within the
     usable window AND
     3. The next byte to be received must be less than or equal than
     the last byte in the received segment AND
     4. The last byte in the rcvd data segment must be inside the usable window
  */
  if (/* 1 */ (session.rcv_nxt <= seq) && 
      /* 2 */ (seq < (session.rcv_nxt + session.rcv_wnd))  &&
      /* 3 */ (session.rcv_nxt <= (seq + datalen)) && 
      /* 4 */ ((seq + datalen - 1) < (session.rcv_nxt + session.rcv_wnd))) {

    /* 
     * we don't want to deal with FINs that may arrive while there is still
     * some data pending. 
     */

    /* Note: This is the part  we have to modify to implement
       the security part of the Bytecounting test */

    int start, end; 
    if (seq == session.rcv_nxt) {

      start = seq - session.irs ; 
      end = start + datalen; 
      if (session.debug) {
	printf ("rcvd = %d-%d\n", start, end);
      }
      for (i = start ; i < end ; i++) {
	session.dataRcvd[i] = 1 ; 
      }

    }

    start = session.rcv_nxt - session.irs; 
    end = session.mss * session.maxpkts; 
    
    last_rcv_nxt = session.rcv_nxt;
    for (i = start ; i < end ; i ++) {
      if (session.dataRcvd[i] == 0) {
	break ;
      }
      last_rcv_nxt++;
    }

    if (session.bytecounting_type != SECURITY_MODE_GENERIC) {

      session.rcv_nxt = last_rcv_nxt;

    }else {

      /* Security case: control number of bytes covered per ACK */
      if (last_rcv_nxt != session.rcv_nxt) {

	/* number of ACKs to be sent */
	num_acks = (int)ceil((double) datalen / (double)session.ack_bytes);      
	
	printf("num_new_bytes: %d num_acks: %d\n",
	       last_rcv_nxt - session.rcv_nxt,
	       num_acks);

	for (i = 1; i < num_acks; i++) {

	  session.rcv_nxt += session.ack_bytes;

	  if (session.verbose) {
	    printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt - session.irs);
	  }
	  SendSessionPacket(&ackpkt, sizeof(struct IPPacket), TCPFLAGS_ACK, 0, 0);
	  acks++;
	}

      }
    }
  }

  /* Performance case: control ACK "spacing" */
  if (history[session.hsz  - 1].type == RCVD) {
    pkts_rcvd_no_ack_snt += 1;  
  }
  
  printf("pkts_rcvd_no_ack_snt: %d, session.ack_rate: %d\n", pkts_rcvd_no_ack_snt, session.ack_rate);
  if (pkts_rcvd_no_ack_snt == session.ack_rate) {
    
    session.rcv_nxt = last_rcv_nxt;

    if (session.verbose) {
      printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt - session.irs);
    }
    
    SendSessionPacket(&ackpkt, sizeof(struct IPPacket), TCPFLAGS_ACK, 0, 0);
    pkts_rcvd_no_ack_snt = 0;
    acks++;

  }
  
  if (session.debug) {
    printf("Out of BCSecCongAvoidAckData...\n");
  }
  
}
