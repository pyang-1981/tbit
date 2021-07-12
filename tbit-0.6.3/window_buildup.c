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
#include "window_buildup.h"

extern struct TcpSession session;
extern struct History history[];

void WindowBuildUpTest(uint32 sourceIpAddress, 
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
    perror("ERROR: Could not allocate opt:");
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
		       1, /* start with a CWND = 1 */
		       1000,
		       0,
		       0) == 0) {  
    printf("ERROR: Couldn't establish session\n");
    Quit(NO_SESSION_ESTABLISH);

  }

  SendRequest(session.filename, (void *)WindowBuildUpAckData); 
  rcvData(WindowBuildUpAckData);

  free(opt);

}

void WindowBuildUpAckData(struct IPPacket *p) 
{

  uint32 seq = history[session.hsz-1].seqno;
  uint16 datalen = history[session.hsz-1].dlen;
  int fin = history[session.hsz-1].fin; 
  int i;
  struct IPPacket *ackpkt;
  static int seen_datalen = 0;

  if (session.debug) {
    printf("In WindowBuildUpAckData...\n");
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

    if (session.verbose) {
      printf ("r %f %d %d\n", GetTime() - session.epochTime, 
	      seq - session.irs, seq - session.irs + datalen);
    }

    session.totDataPktsRcvd++ ;
  }
  
  if(session.maxseqseen < seq + datalen - 1) {

    session.maxseqseen = seq + datalen - 1; 

  }else {
    
    int r;
    if (datalen > 0) {

      r = reordered(p);
      if (r == 1 || r == 3) {

	printf("Reordering!...\n");

      }else {

	printf("RESULT: LastWindow: %d\n", session.totDataPktsRcvd - 7);
	Quit(SUCCESS);
      
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


  if (session.totDataPktsRcvd <= 6) {

    /* If RWND is less that the initial RWND for case 2 (8000/mss), 
     * add one full segment to it on each sent ACK */

    if (session.totDataPktsRcvd == 6) {
      session.rcv_wnd = 10000; /* Very large RWND */
    }
    
    /* Allocate space for ACK packet */
    ackpkt = AllocateIPPacket(0,0,0,"TotData (ACK)");

    if (session.verbose) {
      printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt - session.irs);
    }
   
    SendSessionPacket (ackpkt, 
		       sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		       TCPFLAGS_ACK, 
		       0,
		       0, 
		       0);

    free(ackpkt->ip);
    free(ackpkt->tcp);
    free(ackpkt);
    
  }

  if (fin) {
    printf("Not enough packets\nRETURN CODE: %d\n", NOT_ENOUGH_PKTS);
    Quit(NOT_ENOUGH_PKTS); 
  }


  if (session.debug) {
    printf("Out of WindowBuildUpAckData...\n");
  }

}

