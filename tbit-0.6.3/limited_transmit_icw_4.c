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
#include "limited_transmit_icw_4.h"

extern struct TcpSession session;
extern struct History history[];

/*
 * Limited transfer goal: Effectively recover lost segments when a
 * connection's cogestion window is small.  Small congestion window:
 * it can be due to several reasons:
 * 1. - Limited amount of data to be sent
 * 2. - Limit imposed by receiver's advertised congestion window
 * 3. - Constrains imposed by the E2E congestion control over a
        connection with a small BW-delay product.
 * Test Purpose: Check is a new data segment is sent with each of the
 * first two duplicate ACKs that arrive at the sender. The test forces
 * a small window according to condition (2) above.
 */

void LimitedTransmit_ICW_4_Test(uint32 sourceIpAddress, 
				uint16 sourcePort, 
				uint32 targetIpAddress, 
				uint16 targetPort, 
				int mss) 
{

  int optlen; 
  char *opt; 

  /* TCP Options */
  optlen = 4 ;
  if ((opt = (char *)calloc(sizeof(uint8), optlen)) == NULL)	{
    printf("ERROR: Could not allocate opt\nRETURN CODE: %d\n", ERR_MEM_ALLOC);
    Quit(ERR_MEM_ALLOC);
  }

  /* mss option */
  opt[0] = (uint8)TCPOPT_MAXSEG; 
  opt[1] = (uint8)TCPOLEN_MAXSEG; 
  *((uint16 *)((char *)opt + 2)) = htons(mss);

  /* End-of-List Option */
  opt[4] = (uint8)TCPOPT_EOL;
  
  if (EstablishSession(sourceIpAddress,
		       sourcePort,
		       targetIpAddress,
		       targetPort,
		       0,    /* ip_opt len */
		       NULL, /* ip_opt pointer */
		       mss, 
		       optlen, 
		       opt,
		       8000 / mss,   /* Advertised RWND */
		       100000,
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\nRETURN CODE: %d\n", NO_SESSION_ESTABLISH);
    Quit(NO_SESSION_ESTABLISH);
  }

  SendRequest(session.filename, (void *)LimitedTransmitICW4AckData); 
  rcvData(LimitedTransmitICW4AckData);

}


void LimitedTransmitICW4AckData(struct IPPacket *p) 
{

  uint32 seq = history[session.hsz - 1].seqno;
  uint16 datalen = history[session.hsz - 1].dlen;
  int fin = history[session.hsz - 1].fin; 
  int i;
  struct IPPacket *ackpkt;
  static int seen_datalen = 0;
  int dropForLimitedTransmitTest = 0;
  static int initWin = 4;
  static int start_test_pkt = 1;
  int pkt_number = 0;
  static int last_seen_datalen = 0;
  static int ack_number = 0;
  static int packets_seen[8];
  static float highest_pkt_arr_time = 0;
  static float last_ack_snt_time = 0;

  if (session.debug) {
    printf("In LimitedTransmitICW3AckData...\n");
  }

  if (seen_datalen < datalen) {
    seen_datalen = datalen;
  }

  if (datalen > session.mss) {
    printf ("ERROR: mss=%d datalen=%d\nRETURN_CODE: %d\n", session.mss, datalen, MSS_ERR);
    Quit(MSS_ERR);
  }

  if (datalen > 0) {

    if (seq - session.irs == 1) { 

      char *http_code = (char *)calloc(4, sizeof(char));

      /* Response to request packet --> check HTTP response code */
      PrintTcpPacket(p);
      memcpy(http_code, ((char *)(p->tcp) + sizeof(struct TcpHeader) + history[session.hsz - 1].optlen + 9), 3);
      if (strncmp(http_code, HTTP_OK, 3) != 0) {
	printf("HTTP ERROR - HTTP RESPONSE CODE: %s\nRETURN CODE: %d\n", http_code, atoi(http_code));
	Quit(atoi(http_code));
      }

      printf("HTTP RESPONSE CODE: %s\n", http_code);

    }

    if (session.verbose) {
      printf ("r %f %d %d\n", GetTime() - session.epochTime, seq - session.irs, seq-session.irs + datalen);
    }

    pkt_number = (int)ceil((float)(seq + datalen - 1 - session.irs) / (float)seen_datalen);

    if (packets_seen[pkt_number] == 0) {
      session.totDataPktsRcvd++;
      packets_seen[pkt_number] = 1;
    }

    if (last_seen_datalen != datalen) {
      if (last_seen_datalen != 0 && fin != 1) {
	printf("ERROR: Variation in packet size (%d, %d)! Ignore result...\nRETURN CODE: %d", 
	       last_seen_datalen, datalen, PKT_SIZE_CHANGED);
	Quit(PKT_SIZE_CHANGED);
      }else {
	last_seen_datalen = datalen;
      }
    }

  }

  if(session.maxseqseen < seq + datalen - 1) {

    session.maxseqseen = seq + datalen - 1; 
    highest_pkt_arr_time = GetTime() - session.epochTime;

  }else {

    int r = reordered(p);

    if ((r == 2 || r == 3) && pkt_number == 2) {
      session.totDataPktsRcvd = initWin + 3;
    }

  }


  if (pkt_number == start_test_pkt + 1) {

    dropForLimitedTransmitTest = 1;
    if (session.verbose) {
      printf ("d %f %d %d\n", GetTime() - session.epochTime, seq-session.irs, seq-session.irs+datalen);
    }

  }else {

    dropForLimitedTransmitTest = 0;

  }

  if(session.totDataPktsRcvd == initWin + 3) {
    
    int last_pkt_rcvd;
    int highest_pkt_rcvd;

    last_pkt_rcvd = (int)ceil((float)(seq + datalen - 1 - session.irs) / (float)seen_datalen);
    highest_pkt_rcvd = (int)ceil((float)(session.maxseqseen - session.irs) / (float)(seen_datalen));

    printf("RESULT: session.rtt = %f mss = %d InitWin: %d HighestPktRcvd: %d LastPkt: %d ", 
	   session.rtt, 
	   seen_datalen, 
	   initWin, 
	   highest_pkt_rcvd,
	   last_pkt_rcvd);    


    if (highest_pkt_arr_time - last_ack_snt_time < 0.75 * session.rtt) {
      highest_pkt_rcvd =  0;
    }

    if (highest_pkt_rcvd >= initWin + 3) {

      printf("Limited Transmit IS IMPLEMENTED\n");

    }else {

      printf("Limited Transmit IS NOT IMPLEMENTED\n");

    }      

    Quit(SUCCESS);

  }


  if (datalen > 0 && dropForLimitedTransmitTest == 0) {

    /* from TCP/IP vol. 2, p 808 */
    if ((session.rcv_nxt <= seq) && (seq < (session.rcv_nxt + session.rcv_wnd))  &&
	(session.rcv_nxt <= (seq + datalen)) && ((seq + datalen - 1) < (session.rcv_nxt + session.rcv_wnd))) {

      int start, end; 
      start = seq - session.irs; 
      end = start + datalen; 
      
      for (i = start ; i < end ; i++) {
	session.dataRcvd[i] = 1 ; 
      }
	
      if (session.debug) {
	printf ("rcved = %d-%d\n", start, end);
      }

      if (pkt_number == 1) {

	start = session.rcv_nxt - session.irs ; 
	end = session.mss * session.maxpkts ; 
	
	for (i = start; i < end; i ++) {
	  if (session.dataRcvd[i] == 0) {
	    break ;
	  }
	  session.rcv_nxt++;
	}
      }
    }

    if (pkt_number == 1 || pkt_number > 4) {

      last_ack_snt_time = GetTime() - session.epochTime;

      /* Allocate space for ACK packet */
      ackpkt = AllocateIPPacket(0,0,0,"TotData (ACK)");

      /* Send ACK pkt */
      SendSessionPacket(ackpkt, 
			sizeof(struct IpHeader) + sizeof(struct TcpHeader),
			TCPFLAGS_ACK, 
			0,
			0, 
			0);

      /* Should check for unwanted reordering */
      if (datalen > 0 && session.verbose) {
	printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt - session.irs);
      }
  
      free(ackpkt);

      ack_number += 1;            
      
    }
  }


  if (fin) {
    printf("Not enough packets....\nRETURN CODE: %d\n", NOT_ENOUGH_PKTS);
    Quit(NOT_ENOUGH_PKTS); 
  }

  if (session.debug) {
    printf("Out of LimitedTransmitICW1AckData...\n");
  }

}





