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
#include "windowhalf.h"

extern struct TcpSession session;
extern struct History history[];

static uint32 droplist[MAXDROP];
static int droppedForWindowHalfTest = 0; 
static double droptime; 

void WindowHalfTest (uint32 sourceIpAddress, uint16 sourcePort, uint32 targetIpAddress, uint16 targetPort, int mss) 
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
		       NULL,  /* ip_opt pointer */
		       mss,
		       optlen,
		       opt,
		       8,  /* Window size,in packets */
		       40, /* Max number of packets */
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\nRETURN CODE: %d", NO_SESSION_ESTABLISH);
    Quit(NO_SESSION_ESTABLISH);
  }

  SendRequest(session.filename, (void *)WindowHalfackData); 
  rcvData (WindowHalfackData);
}

void WindowHalfackData (struct IPPacket *p) 
{

  uint32 seq = history[session.hsz-1].seqno;
  uint16 datalen = history[session.hsz-1].dlen;

  int i; 
  struct IPPacket *ackpkt ; 
  int dropForWindowHalfTest = 0 ;
  int flag = 0; 

  if (session.debug) {
    printf("In WindowHalf ACK Data...\n");
  }

  if (history[session.hsz-1].fin) {
    printf ("ERROR: NOT_ENOUGH_PKTS\nRETURN CODE: %d", NOT_ENOUGH_PKTS);
    Quit(NOT_ENOUGH_PKTS);
  }

  if (datalen > session.mss) {
    printf ("ERROR: MSS_ERR mss=%d datalen=%d\nRETURN CODE: %d", 
	    session.mss, datalen, MSS_ERR);
    Quit(MSS_ERR);
  }

  if ((seq + datalen - session.irs) > session.mss * session.maxpkts) {
    printf ("ERROR: Buffer Overflow: %u %d %u %d %d\nRETURN CODE: %d", 
	    seq, datalen, 
	    session.irs, 
	    seq + datalen - session.irs, 
	    session.mss * session.maxpkts,
	    BUFFER_OVERFLOW);

    Quit(BUFFER_OVERFLOW); 
  }

  if (session.debug) {
    printf ("Datalen = %d\n\n", (int)datalen);
  }

  if (datalen > 0) {

    char *http_code = (char *)calloc(4, sizeof(char));

    if (seq - session.irs == 1) {
      /* Response to request (1st) packet --> check HTTP response code */
      memcpy(http_code, ((char *)(p->tcp) + sizeof(struct TcpHeader) + history[session.hsz - 1].optlen + 9), 3);
      if (strncmp(http_code, HTTP_OK, 3) != 0) {
	printf("HTTP ERROR - HTTP RESPONSE CODE: %s\nRETURN CODE: %d\n", http_code, atoi(http_code));
	Quit(atoi(http_code));
      }
    }

    session.totDataPktsRcvd++ ;

    if (session.verbose) {
      printf ("r %f %d %d\n", GetTime() - session.epochTime, seq-session.irs, seq-session.irs+datalen);
    }

  }

  if(session.maxseqseen <= seq + datalen - 1) {

    session.maxseqseen = seq + datalen - 1; 

  }else {

    if (datalen > 0) {
      
      printf ("##### Out-of-sequence packet %f %d %d \n", 
	      GetTime() - session.epochTime, 
	      seq - session.irs, 
	      seq - session.irs + datalen);

      session.totOutofSeq++ ;
      
      if (session.totOutofSeq == 1) {
	flag = 1;
      }

      /* If packet was dropped by test, ignore reordered retransmission */
      if (!dropped(seq) && (droppedForWindowHalfTest == 0)) {

	if (reordered(p) == 1) {

	  printf ("ERROR: Reordering before test completion\n");
	  Quit(UNWANTED_PKT_REORDER);

	}else {

	  printf ("ERROR: unwanted packet drop before test completion\n");
	  Quit(UNWANTED_PKT_DROP); 

	}
      }
    }
  }

  if ((session.totDataPktsRcvd > session.maxpkts) || (session.totOutofSeq > 1)) {

    if (session.totOutofSeq < 1) {

      printf("ERROR: NOT ENOUGH_PKTS\nRETURN CODE: %d\n", NOT_ENOUGH_PKTS);
      Quit(NOT_ENOUGH_PKTS);

    } else {

      CheckHalf() ;
      Quit(SUCCESS); 

    }
  }

  /*
   * do not ack anything after retransmit of 15
   */

  if ((session.totDataPktsRcvd == 15) || ((session.totOutofSeq > 0) && (flag == 0))) {

    if (droppedForWindowHalfTest >= MAXDROP) {
      printf ("ERROR: Too many drops\nRETURN CODE: %d\n", TOO_MANY_DROPS);
      Quit(TOO_MANY_DROPS);
    }

    droplist[droppedForWindowHalfTest++] = seq;
    droptime = GetTime ();
    printf ("##### droppacket %f %d %d\n", GetTime()-session.epochTime, seq-session.irs, seq-session.irs+datalen);
    dropForWindowHalfTest = 1;

  }
	
  if (session.debug) {
    printf ("dlen=%d reno=%d seq=%u rcv_nxt=%u rcv_wnd=%u\n", datalen, droplist[droppedForWindowHalfTest-1],
	    seq, session.rcv_nxt, session.rcv_wnd);
  }

  /* from TCP/IP vol. 2, p 808 */
  if ((datalen > 0) && 
      (dropForWindowHalfTest == 0) &&
      (session.rcv_nxt <= seq) && (seq < (session.rcv_nxt + session.rcv_wnd))  &&
      (session.rcv_nxt <= (seq + datalen)) && ((seq+datalen - 1) < (session.rcv_nxt + session.rcv_wnd))) {

    int start = seq - session.irs ; 
    int end = start + datalen ; 

    if (session.debug) {
      printf ("rcved = %d-%d\n", start, end);
    }

    for (i = start ; i < end ; i++) {
      session.dataRcvd[i] = 1 ; 
    }

    start = session.rcv_nxt - session.irs ; 
    end = session.mss * session.maxpkts ; 
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

  if ((datalen > 0) && (dropForWindowHalfTest == 0)) {

    if (session.debug) { 
      printf ("sending ack\n");
    }

    busy_wait(PLOTDIFF);

    /* Allocate ACK packet */
    ackpkt = AllocateIPPacket(0, 0, 0, "WindowHalf (ACK)");

    SendSessionPacket (ackpkt, 
		       //sizeof(struct IPPacket), 
		       sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		       TCPFLAGS_ACK, 
		       0,
		       0, 
		       0);

    if (session.verbose) {
      printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt-session.irs);
    }

    free(ackpkt);

  }

}

void CheckHalf () 
{
  int x = session.maxseqseen - session.irs; 
  int y = session.rcv_nxt - session.irs; 
  int z = x - y; 

  if (z > (5 * session.mss)) {

    printf ("RESULT: WINDOW NOT HALVED\n");

  }else {

    printf ("RESULT: WINDOW HALVED ");

  }

  printf ("%d Bytes outstanding\n", 
	  session.maxseqseen - session.rcv_nxt + 1);
}

int dropped (uint32 seq) {

  int i;
  for (i = 0 ; i < droppedForWindowHalfTest; i++) {
    if (seq == droplist[i]) {
      return 1; 
    }
  }
  return 0;

}
