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
#include "icw_perf.h"

extern struct TcpSession session;
extern struct History history[];

void ICWPerformanceTest(uint32 sourceIpAddress, 
			uint16 sourcePort, 
			uint32 targetIpAddress, 
			uint16 targetPort, 
			int mss,
			int type) 
{

  int optlen; 
  char *opt; 
  int rwnd;

  /* TCP Options */
  optlen = 4 ;
  if ((opt = (char *)calloc(sizeof(uint8), optlen)) == NULL)	{
    perror("ERROR: Could not allocate opt:");
    Quit(ERR_MEM_ALLOC);
  }

  /* mss option */
  opt[0] = (uint8)TCPOPT_MAXSEG; 
  opt[1] = (uint8)TCPOLEN_MAXSEG; 
  *((uint16 *)((char *)opt + 2)) = htons(mss);

  /* End-of-List Option */
  opt[4] = (uint8)TCPOPT_EOL;

  if (type == 1) {
    printf("Executing ICW type 1...\n");
    rwnd  = 1;    /* RWND= 1 + i, i (ack no)=0,1,2,... */
  }else {
    rwnd = 10000;
  }

  if (EstablishSession(sourceIpAddress,
		       sourcePort,
		       targetIpAddress,
		       targetPort,
		       0,    /* ip_opt len */
		       NULL, /* ip_opt pointer */
		       mss, 
		       optlen, 
		       opt,
		       rwnd,
		       1000000,
		       0,
		       0) == 0) {  
    printf("ERROR: Couldn't establish session\n");
    Quit(NO_SESSION_ESTABLISH);

  }

  SendRequest(session.filename, (void *)ICWPerformanceAckData); 
  rcvData(ICWPerformanceAckData);

  free(opt);

}

void ICWPerformanceAckData(struct IPPacket *p) 
{

  uint32 seq = history[session.hsz-1].seqno;
  uint16 datalen = history[session.hsz-1].dlen;
  int fin = history[session.hsz-1].fin; 
  int i;
  struct IPPacket *ackpkt;
  static int seen_datalen = 0;

  if (session.debug) {
    printf("In ICWPerformanceAckData...\n");
  }

  if (seen_datalen < datalen) {
    seen_datalen = datalen;
  }

  if (datalen > session.mss) {
    printf ("ERROR: mss=%d datalen=%d\n", session.mss, datalen);
    Quit(MSS_ERR);
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
    }

    session.totDataPktsRcvd ++ ;

    if (session.verbose) {
      printf ("r %f %d %d\n", GetTime() - session.epochTime, 
	      seq - session.irs, seq - session.irs + datalen);
    }
  }
  
  if(session.maxseqseen < seq + datalen - 1) {

    session.maxseqseen = seq + datalen - 1; 

  }else {
    
    int r;

    if (datalen > 0) {

      r = reordered(p);
      switch (r) {
      case 1:
	printf("Reordering!...\n");
	break;
	
      case 2:
	printf("Drop! (RTO)...\n");
	session.num_unwanted_drops += 1;
	session.num_rtos += 1;
	break;
	
      case 3:
	printf("Drop! (3 Dup Acks))...\n");
	session.num_unwanted_drops += 1;
	session.num_dupack_ret += 1;
	break;
      }
    }
  }

  /* from TCP/IP vol. 2, p 808 */
  if ((session.rcv_nxt <= seq) && (seq < (session.rcv_nxt + session.rcv_wnd))  &&
      (session.rcv_nxt <= (seq + datalen)) && ((seq + datalen - 1) < (session.rcv_nxt + session.rcv_wnd))) {
    /* 
     * we don't want to deal with FINs that may arrive while there is still
     * some data pending. 
     */

    int start, end; 
    start = seq - session.irs ; 
    end = start + datalen ; 

    if (session.debug) {
      printf ("rcved = %d-%d\n", start, end);
    }

    for (i = start ; i < end ; i++) {
      session.dataRcvd[i] = 1 ; 
    }

    start = session.rcv_nxt - session.irs ; 
    end = session.mss*session.maxpkts ; 
    for (i = start ; i < end ; i ++) {
      if (session.dataRcvd[i] == 0) {
	break ;
      }
      session.rcv_nxt++ ;
    }
  }

  if (session.verbose) {
    printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt - session.irs);
  }

  /* If RWND is less that the initial RWND for case 2 (8000/mss), 
   * add one full segment to it on each sent ACK */
  if (session.totDataPktsRcvd >= 1) {
    /*if ((float)session.rcv_wnd / session.mss < (double)8000 / session.mss) {*/
    if ((float)session.rcv_wnd / session.mss < 4) {
      session.rcv_wnd += session.mss;
    }else {
      session.rcv_wnd = 10000; /* Very large RWND */
    }

  }

  /* Allocate space for ACK packet */
  ackpkt = AllocateIPPacket(0,0,0,"TotData (ACK)");


  SendSessionPacket (ackpkt, 
		     sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		     TCPFLAGS_ACK, 
		     0,
		     0, 
		     0);

  free(ackpkt->ip);
  free(ackpkt->tcp);
  free(ackpkt);

  if (fin) {

    double data, ttime, tput;

    if (session.totDataPktsRcvd == 0) {

      printf("Not enough packets\nRETURN CODE: %d\n", NOT_ENOUGH_PKTS);
      Quit(NOT_ENOUGH_PKTS);

    }else {

      data = session.rcv_nxt - session.irs;
      ttime = GetTime() - session.start_time;
      tput = (data * 8) / ttime;
      printf("ICWPerfTotdata: %d mss: %d pkts: %d Time: %.4f Tput: %.4f Drops: %d Reord: %d\n",
	     session.rcv_nxt - session.irs,	     
	     seen_datalen, 
	     session.totDataPktsRcvd,
	     ttime,
	     tput,
	     session.num_unwanted_drops,
	     session.num_reordered);

      printf("session.rtt = %f\n", session.rtt);
      Quit(SUCCESS); 
    }

  }


  if (session.debug) {
    printf("Out of ICWPerformanceAckData...\n");
  }

}

int ExtractInitWin() {

  int i, win;
  double ts1, ts2, elapsed;
  
  win = 0;
  for (i = 0; i < session.hsz - 1; i++) {

    if ((history[i].type == RCVD) && (history[i].dlen > 0)) {

      if (win == 0) {

	ts1 = history[i].timestamp; 
	win += 1;

/* 	printf("i: %d %f 0.0 %f type: %d, datalen: %d\n", */
/* 	       i, */
/* 	       history[i].timestamp, */
/* 	       0.7 * session.rtt, */
/* 	       history[i].type, */
/* 	       history[i].dlen); */

      }else {
	
	ts2 = history[i].timestamp; 
	elapsed = ts2 - ts1;

/* 	printf("i: %d %f %f %f type: %d, datalen: %d\n", */
/* 	       i, */
/* 	       history[i].timestamp, */
/* 	       elapsed, */
/* 	       0.7 * session.rtt, */
/* 	       history[i].type, */
/* 	       history[i].dlen); */

	if (elapsed  > 0.7 * session.rtt) {

	  return win > 1?win:1;

	}else {

	  win += 1;

	}
      }
    }
  }

  return win;

}
