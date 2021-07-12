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
#include "bc_sec_slowstart_limit.h"

extern struct TcpSession session;
extern struct History history[];

void BCSecSlowStartLimitTest(uint32 sourceIpAddress, uint16 sourcePort, \
			     uint32 targetIpAddress, uint16 targetPort, \
			     int mss, int ack_bytes)
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
  
  session.ack_bytes = ack_bytes;
  SendRequest(session.filename, (void *)BCSecSlowStartLimitAckData); 
  rcvData(BCSecSlowStartLimitAckData);

}

void BCSecSlowStartLimitAckData(struct IPPacket *p) 
{

  uint32 seq = history[session.hsz-1].seqno;
  uint16 datalen = history[session.hsz-1].dlen;
  int fin = history[session.hsz - 1].fin; 
  int i, num_acks;
  struct IPPacket ackpkt ;
  static int seen_datalen = 0;
  double arrival_time = 0.0;
  static double first_pkt_arrival_time = 0.0;
  static int num_pkts_second_round = 0;
  static int acks = 0;

  if (session.debug) {
    printf("In BCSecSlowStartAckData...\n");
  }

  if (seen_datalen < datalen) {
    seen_datalen = datalen;
  }

  if (datalen > session.mss) {
    printf ("ERROR: mss=%d datalen=%d\nRETURN CODE: %d", session.mss, datalen, MSS_ERR);
    Quit(MSS_ERR);
  }

  if (fin) {
    /* Need enough packets to go beyond initial cwnd */
    printf("Not enough pakets\nRETURN CODE: %d\n", NOT_ENOUGH_PKTS);
    Quit(NOT_ENOUGH_PKTS);
  }

  if (datalen > 0) {

    arrival_time = GetTime() - session.epochTime;
    if (session.totDataPktsRcvd == 0) {

      first_pkt_arrival_time = arrival_time;

    }

    if(session.maxseqseen < seq + datalen - 1) {
      
      session.maxseqseen = seq + datalen - 1; 
      if (arrival_time > first_pkt_arrival_time + 0.9 * session.rtt) {
	num_pkts_second_round++;
      }
      
    }else {

      printf("session.rtt = %f\nACKS: %d\nTRIGGERED: %d\n", 
	     0.9 * session.rtt, 
	     acks, 
	     num_pkts_second_round);
      Quit(SUCCESS);

    }


    if (session.verbose) {
      printf ("r %f %d %d %f\n", 
	      arrival_time,
	      seq - session.irs, 
	      seq - session.irs + datalen,
	      arrival_time - first_pkt_arrival_time);
    }

    session.totDataPktsRcvd++;

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

    if (session.totDataPktsRcvd > 1) {
      start = session.rcv_nxt - session.irs; 
      end = session.mss * session.maxpkts; 
      for (i = start ; i < end ; i ++) {
	if (session.dataRcvd[i] == 0) {
	  break ;
	}
	session.rcv_nxt++;
      }
    }
  }

  /* Send appropriate number acks covering bytes in first packet */
  if (session.totDataPktsRcvd == 1) {
    
    num_acks = (int)ceil((double) datalen / (double)session.ack_bytes);      
    printf("DATALEN: %d ackbytes: %d num_acks: %d\n", datalen, session.ack_bytes, num_acks);	
    for (i = 1; i <= num_acks; i++) {
      
      session.rcv_nxt += session.ack_bytes;

      if (session.verbose) {
	printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt - session.irs);
      }
      SendSessionPacket(&ackpkt, sizeof(struct IPPacket), TCPFLAGS_ACK, 0, 0);
      acks++;
    }

  } 

  if (session.debug) {
    printf("Out of BCSecSlowStartAckData...\n");
  }
  
}
