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
#include "bc_slowstart.h"

extern struct TcpSession session;
extern struct History history[];

void BCSlowStartTest(uint32 sourceIpAddress, uint16 sourcePort, \
		     uint32 targetIpAddress, uint16 targetPort, \
		     int mss)
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
		       0,     /* ip_optlen */
		       NULL,  /* ip_opt pointer */
		       mss, 
		       optlen, 
		       opt,
		       1, /* Start with a RWND of 1 segment */
		       /* 8000/mss, */
		       1000,
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\n");
    Quit(NO_SESSION_ESTABLISH);

  }
  
  SendRequest(session.filename, (void *)BCSlowStartAckData); 
  rcvData(BCSlowStartAckData);

  free(opt);
}

void BCSlowStartAckData(struct IPPacket *p) 
{

  uint32 seq = history[session.hsz - 1].seqno;
  uint16 datalen = history[session.hsz-1].dlen;
  int fin = history[session.hsz - 1].fin; 
  int i;
  struct IPPacket *ackpkt;
  static int seen_datalen = 0;
  static int bc_activated = 0;
  static int end_acking = 0;
  static int expected_num_pkts = 1;
  static int last_window = 0;


  if (session.debug) {
    printf("In BCSlowStartAckData...\n");
  }
  
  if (seen_datalen < datalen) {
    seen_datalen = datalen;
  }
  
  if (datalen > session.mss) {
    printf ("ERROR: mss=%d datalen=%d\nRETRUN CODE: %d\n", 
	    session.mss, 
	    datalen,
	    MSS_ERR);
    Quit(MSS_ERR);
  }

  if (fin) {
    printf("Not enough pakets\nRETURN CODE: %d\n", NOT_ENOUGH_PKTS);
    Quit(NOT_ENOUGH_PKTS);
  }
  
  if (datalen > 0) {
    
    if (seq - session.irs == 1) {

      char *http_code = (char *)calloc(4, sizeof(char));
      /* Response to request packet --> check HTTP response code */
      memcpy(http_code, ((char *)(p->tcp) + sizeof(struct TcpHeader) + history[session.hsz - 1].optlen + 9), 3);
      if (strncmp(http_code, HTTP_OK, 3) != 0) {
	printf("HTTP ERROR - HTTP RESPONSE CODE: %s\nRETURN CODE: %d\n", http_code, atoi(http_code));
	Quit(atoi(http_code));
      }

      printf("HTTP RESPONSE CODE: %s\n", http_code);

      free(http_code);

    }
    
    if (session.verbose) {
      printf ("r %f %d %d\n", 
	      GetTime() - session.epochTime,
	      seq - session.irs, 
	      seq - session.irs + datalen);
    }



    if (session.maxseqseen < seq + datalen - 1) { /* in-sequence packet */

      session.maxseqseen = seq + datalen - 1; 

    }else { /* Out-of-sequence packet */

      int found = 0;

	/* Check for a retransmission */
	for (i = 0; i < session.hsz - 1; i++) {
	  if ((history[i].type == RCVD) && 
	      (history[i].dlen > 0)    && 
	      (history[i].seqno == seq) &&
	      (history[i].nextbyte == seq + datalen)) {
	    printf("Retransmission detected...\n");
	    found = 1;
	    break;
	  }
	}

	if (found) {
	  int diff;
	  diff = last_window - 4;
	  printf("RESULT: session.rtt = %f ", session.rtt);
	  printf("LastWindow: %d ", last_window);
	  
	  if (diff ==  1) {
	    
	    printf("LIMIT: %d PACKET_COUNTING\n", diff);
	    Quit(SUCCESS);

	  }else {

	    if (diff > 1) {

	      printf("LIMIT: %d APPROPRIATE_BYTE_COUNTING\n",  diff);
	      Quit(SUCCESS);

	    }else {
	      
	      printf("UNKNOWN_CASE diff: %d\nRETURN CODE: %d", diff, UNKNOWN_BEHAVIOR);	    
	      Quit(UNKNOWN_BEHAVIOR);

	    }
	    
	  }	  
	  
	  Quit(SUCCESS);
	  
	}
    }

    session.totDataPktsRcvd++;
    last_window += 1;

    switch (session.totDataPktsRcvd) {

    case 1: /* Current CWND = 1 Pkt */
      session.rcv_wnd = 2 * session.mss;
      last_window = 0;
      expected_num_pkts = 3;
      break;
      
    case 3: /* Current CWND = 2 Pkt */
      session.rcv_wnd = 4 * session.mss;
      expected_num_pkts = 7;
      last_window = 0;
      bc_activated = 1;
      break;

    case 7: /* Current CWND = 4 Pkt - blow cwnd out */
      session.rcv_wnd = 100 * session.mss;
      last_window = 0;
      expected_num_pkts = 15;
      break;
    }
    //printf("pkts: %d, RWND: %d exp: %d\n", session.totDataPktsRcvd, session.rcv_wnd, expected_num_pkts);

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

    int start, end; 

    start = seq - session.irs ; 
    end = start + datalen; 

    if (session.debug) {
      printf ("rcvd = %d-%d\n", start, end);
    }

    for (i = start ; i < end ; i++) {
      session.dataRcvd[i] = 1 ; 
    }

    start = session.rcv_nxt - session.irs; 
    end = session.mss * session.maxpkts; 

    for (i = start ; i < end ; i ++) {
      if (session.dataRcvd[i] == 0) {
	break;
      }
      session.rcv_nxt++;
    }
  }

  /* Allocate IP ACK packet */
  ackpkt = AllocateIPPacket(0, 0, 0, "BCSlowStart (ACK)");

  /* Before window of desired size is reached, ack every incoming packet */
  if (bc_activated == 0) { 
  
    if (session.verbose && datalen > 0) {
      printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt - session.irs);
    }

    SendSessionPacket(ackpkt, 
		      sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		      TCPFLAGS_ACK, 
		      0 /* ip_opt_len */, 
		      0 /* tcp_opt len */, 
		      0 /* tos */);
  } 
  
  /* After window of desired size is reached, ack whole window of packets*/
  if (bc_activated == 1 && (session.totDataPktsRcvd == 3 || session.totDataPktsRcvd == 7)) {
    //if (bc_activated == 1 && (session.totDataPktsRcvd == 3 ||
    //			    session.totDataPktsRcvd == 4 ||
			    //session.totDataPktsRcvd == 5 ||
			    //session.totDataPktsRcvd == 6 ||
    //		    session.totDataPktsRcvd == 7)) {
    
    if (session.verbose) {
      printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt - session.irs);
    }
    
    SendSessionPacket(ackpkt, 
		      sizeof(struct IpHeader) + sizeof(struct TcpHeader), 
		      TCPFLAGS_ACK,
		      0, /* ip_opt_len */ 
		      0, /* tcp_opt len */ 
		      0  /* tos */); 

    end_acking++;

  } 

  free(ackpkt);

  if (session.debug) {
    printf("Out of BCSlowStartAckData...\n");
  }
  
}
