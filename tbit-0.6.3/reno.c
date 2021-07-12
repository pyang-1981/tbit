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
#include "tbit.h"
#include "history.h"
#include "reno.h"

#define MAXRXMT 20  
#define MAXTO 20  

extern struct TcpSession session;
extern struct History history[];

static char *renoVersionNames [] = {
	"Uncategorized", 
	"Tahoe", 
	"TahoeNoFR", 
	"Reno", 
	"NewReno",
	"AggresiveReno", 
	"AggresiveTahoeNoFR",
	"RenoPlus",
	"RenoNS",
	"AggresiveFastRetransmit"};

static uint32 renoDrop[2] = {0,0}; 
static int droppedForRenoTest; 

void RenoTest(uint32 sourceIpAddress, uint16 sourcePort, uint32 targetIpAddress, uint16 targetPort, int mss) 
{
  int optlen; 
  char *opt; 
  
  optlen = 4 ;
  if ((opt=(char *)calloc(sizeof(uint8), optlen)) == NULL)	{
    printf("ERROR: Could not allocate opt\nRETURN CODE: %d\n", ERR_MEM_ALLOC);
    Quit(ERR_MEM_ALLOC);
  }

  /* mss option */
  opt[0] = (uint8)TCPOPT_MAXSEG ; 
  opt[1] = (uint8)TCPOLEN_MAXSEG ; 
  *((uint16 *)((char *)opt + 2)) = htons(mss);

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
		       10000,
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\nRETURN CODE: %d\n", NO_SESSION_ESTABLISH);
    Quit(NO_SESSION_ESTABLISH);
  }

  SendRequest(session.filename, (void *)NewRenoackData); 
  rcvData (NewRenoackData);

}


void NewRenoackData (struct IPPacket *p) 
{

  uint32 seq = history[session.hsz - 1].seqno;
  uint8  fin = history[session.hsz - 1].fin;
  uint16 datalen = history[session.hsz - 1].dlen;
  char  *dataptr = history[session.hsz - 1].data;
  int i, out_of_order = 0; 
  struct IPPacket *ackpkt; 
  int dropForRenoTest = 0; 
  int packet_number;
  static int packet_12_dropped = 0;
  static int packet_15_dropped = 0;
  static int pkt_12_ret = 0;
  static int pkt_15_ret = 0;

  /* Keep track of seqno vs. pkt_num received */
  static int *rcvd_pkt_num = NULL;

  if (rcvd_pkt_num == NULL) {
    rcvd_pkt_num = (uint32 *)calloc(session.maxpkts, sizeof(int));
  }
  assert(rcvd_pkt_num != NULL);

  if (session.debug) {
    printf("\n====================\n");
    printf ("datalen = %d\n\n", (int)datalen);
    if (datalen > 0) {
      for (i = 0 ; i < (int)datalen ; i++) {
	printf ("%c", isprint(dataptr[i])?dataptr[i]:' '); 
      }
    }
    printf("\n====================\n");
  }

  if (datalen > session.mss) {
    printf ("ERROR: mss=%d datalen=%d\nRETURN CODE: %d\n", session.mss, datalen, MSS_ERR);
    Quit(MSS_ERR);
  }

  /* keep track of sender's  maximum segment size */
  if (datalen > session.sndmss) {
    session.sndmss = datalen;
  }

  if ((seq - session.irs + datalen) > session.mss * session.maxpkts) {
    printf ("ERROR: buffer overflow: %u %d %u %d %d\nRETURN CODE: %d\n", 
	    seq, datalen, 
	    session.irs, 
	    seq+datalen - session.irs, 
	    session.mss * session.maxpkts,
	    BUFFER_OVERFLOW);
    Quit(BUFFER_OVERFLOW); 
  }


  if(session.maxseqseen < seq + datalen - 1) {

    session.maxseqseen = seq + datalen - 1; 

  }else {

    if (datalen > 0) {

      if (session.verbose) {
	printf ("##### oos packet %f %d %d max=%d\n", 
		GetTime() - session.epochTime, 
		seq - session.irs, 
		seq - session.irs + datalen, 
		session.maxseqseen - session.irs);
      }
      
      if ((seq == renoDrop[0]) || (seq == renoDrop[1])) {
      	session.totOutofSeq++;
      }

      if (reordered(p) != 1) {
	if (seq != renoDrop[0] && seq != renoDrop[1]) {
	  session.num_unwanted_drops += 1;
	  session.ignore_result = 1;
	}

      }else {

	if (seq != renoDrop[0] && seq != renoDrop[1]) {
	  out_of_order = 1;
	}

      }

    }
  }

  if (datalen > 0) {

    char *http_code = (char *)calloc(4, sizeof(char));

    if (seq - session.irs == 1) {
      /* Response to request packet --> check HTTP response code */
      memcpy(http_code, ((char *)(p->tcp) + sizeof(struct TcpHeader) + history[session.hsz - 1].optlen + 9), 3);
      if (strncmp(http_code, HTTP_OK, 3) != 0) {
	printf("HTTP ERROR - HTTP RESPONSE CODE: %s\nRETURN CODE: %d\n", http_code, atoi(http_code));
	Quit(atoi(http_code));
      }
    }
  }

  if (datalen > 0) {

    /*packet_number = session.totDataPktsRcvd;*/
    session.totDataPktsRcvd++;
    packet_number = ceil((float)(seq - session.irs) / (float)session.sndmss);

    if ((packet_number != 0) && (rcvd_pkt_num[packet_number] != 0) && (rcvd_pkt_num[packet_number] != (seq - session.irs))) {
      printf("Inconsistent packet numbering - smaller MSS? ==> Ignore result...\n");
      session.ignore_result = 1;
    }else {
      rcvd_pkt_num[packet_number] = seq - session.irs;
    }
  }

  /* Record number of each received packet */
  history[session.hsz - 1].pkt_num = packet_number;

  /*
   * drop packets for reno version test? 
   *
   */

  /* Keep track of how many times pkt 12 have been retransmitted */
  if ((packet_number == 12) && (packet_12_dropped == 1)) {
    pkt_12_ret += 1;
  }
  if ((packet_number == 12) && (packet_12_dropped == 0)) {

    if (packet_15_dropped == 1) {
      printf("pkt 12 dropped after pkt 15 was dropped ==> Ignore result!\n");
      session.ignore_result = 1;
    }
    packet_12_dropped = 1;
    renoDrop[droppedForRenoTest++] = seq;	
    dropForRenoTest = 1;
    printf("droppedForRenoTest: %d %d\n", droppedForRenoTest, renoDrop[droppedForRenoTest - 1] - session.irs);
    printf ("##### droppacket %f %d %d %d\n", 
	    GetTime() - session.epochTime, 
	    seq - session.irs, 
	    seq - session.irs + datalen,
	    packet_number);

    if (session.verbose) {
      printf ("d %f %d %d %d\n", 
	      GetTime() - session.epochTime, 
	      seq - session.irs, 
	      seq - session.irs + datalen,
	      packet_number);
    }
  }   

  /* Keep track of how many times pkts 15 have been retransmitted */
  if ((packet_number == 15) && (packet_15_dropped == 1)) {
    pkt_15_ret += 1;
  }

  if ((packet_number == 15) && (packet_15_dropped == 0)) {

    if (pkt_12_ret >= 1) {
      printf("pkt 15 dropped after pkt 12 was retransmitted ==> Ignore result!\n");
      session.ignore_result = 1;
    }
    packet_15_dropped = 1;

    renoDrop[droppedForRenoTest++] = seq ;	
    dropForRenoTest = 1;
    printf("droppedForRenoTest: %d %d\n", droppedForRenoTest, renoDrop[droppedForRenoTest - 1] - session.irs);
    printf ("##### droppacket %f %d %d %d\n", 
	    GetTime() - session.epochTime,
	    seq-session.irs, 
	    seq - session.irs + datalen,
	    packet_number);

    if (session.verbose) {
      printf ("d %f %d %d %d\n", 
	      GetTime() - session.epochTime, 
	      seq - session.irs, 
	      seq - session.irs + datalen,
	      packet_number);
    }
  }   

  if (datalen > 0 && session.verbose && dropForRenoTest == 0) {
    
    printf ("r %f %d %d %d %d\n", 
	    GetTime() - session.epochTime, 
	    seq - session.irs, 
	    seq - session.irs + datalen,
	    session.totDataPktsRcvd,
	    packet_number);
  }

  if (session.debug) {
    printf ("dlen=%d reno=%d seq=%u rcv_nxt=%u rcv_wnd=%u\n", datalen, dropForRenoTest, 
	    seq, session.rcv_nxt, session.rcv_wnd);
  }

  /* If received packet does not have to be dropped and the data
   * received falls inside the current congestion window, update state
   * and check if we have enough information already to identify the server
   */

  if ((datalen > 0) && 
      (dropForRenoTest == 0) &&
      (session.rcv_nxt <= seq) && (seq < (session.rcv_nxt + session.rcv_wnd))  &&
      (session.rcv_nxt <= (seq + datalen)) && ((seq + datalen - 1) < (session.rcv_nxt + session.rcv_wnd))) {
    
    int start = seq - session.irs ; 
    int end = start + datalen ; 
    if (session.debug) {
      printf ("rcved = %d-%d\n", start, end);
    }

    for (i = start; i < end; i++) {
      session.dataRcvd[i] = 1; 
    }

    start = session.rcv_nxt - session.irs ; 
    end = session.mss * session.maxpkts ; 

    for (i = start ; i < end ; i ++) {
      if (session.dataRcvd[i] == 0) {
	break ;
      }
      session.rcv_nxt++ ;
    }

    if (session.debug) {
      printf ("rcv_nxt = %u\n", (int)session.rcv_nxt);
    }

    if ((droppedForRenoTest == 2) && (session.rcv_nxt >= 6 * session.mss + renoDrop[1])) {
      /* If packets 12 or 15 retransmitted more than once invalidate the result */
      if ((pkt_12_ret > 1) || (pkt_15_ret > 1)) {
	printf("Pkt 12 retransmitted: %d times, Pkt 15 retransmitted: %d times ==> Ignore rsult...\n",
	       pkt_12_ret, pkt_15_ret);
	session.ignore_result = 1;
      }
      NewWhichReno();
      Quit(SUCCESS);
    }
  }
  
  if (fin) {
    printf("ERROR: NOT_ENOUGH_PKTS\nRETURN CODE: %d\n", NOT_ENOUGH_PKTS);
    Quit(NOT_ENOUGH_PKTS);

  }

  if ((datalen > 0) && (dropForRenoTest == 0)) {

    if (session.debug) { 
      printf ("sending ack\n");
    }
    
    ackpkt = AllocateIPPacket(0,0,0,"Reno");
    
    busy_wait(PLOTDIFF);
    SendSessionPacket (ackpkt, 
		       sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		       TCPFLAGS_ACK, 
		       0, /* ip options length */		     
		       0, /* tcp options length */
		       0);
    
    if (session.verbose) {
      printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt - session.irs);
    }


  }
}


void NewWhichReno () 
{

  struct Rxmt rxmt[MAXRXMT];
  int pkt13_found = 0;
  int pkt16_found = 0;
  int to[MAXTO] ; 
  int i, j ; 
  int numRxmt = 0, numTO = 0 ;	
  int renoversion = Uncategorized ; 
  int firstDropTO = 0;
  int secondDropTO = 0;
  int count = 0; 

  /* 
   * Count retransmissions using a very dumb algo, but what the
   * heck... note that the first pkt can not be a retransmission
   */
  
  for (i = 1; i < session.hsz; i++) {

    if ((history[i].type == RCVD) && (history[i].dlen > 0)) {

      for (j = 0 ; j < i - 1 ; j++) {

	if ((history[j].type == RCVD) && (history[j].dlen > 0) &&
	    (history[j].seqno <= history[i].seqno) &&
	     (history[j].nextbyte > history[i].seqno)) {

	  rxmt[numRxmt].pkt_num = history[i].pkt_num;
	  rxmt[numRxmt].hist_index = i;

	  if (rxmt[numRxmt].pkt_num == 13) {
	    pkt13_found = 1;
	  }

	  if (rxmt[numRxmt].pkt_num == 16) {
	    pkt16_found = 1;
	  }

	  numRxmt++;

	  if (numRxmt == MAXRXMT) {
	    renoversion = Uncategorized ; 
	  }
	  break ;
	}
      }
    }
  }

  printf("Actual RXMT: %d Session RXMT: %d\n", numRxmt, session.totOutofSeq);

  /*
   * Count timeouts. There can not be a timeout 
   * before the first packet.
   */
  
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
	    if (numTO == MAXTO) {
	      renoversion = Uncategorized ; 
	    }
	  }

	} 
      }
    }
  }

  printf("Number of TIMEOUTS: %d\n", numTO);

  /*
   * were there Timeouts for first or second packet that we dropped?
   */
  for (i = 0; i < numTO ; i++) {
    if (history[to[i]].seqno == renoDrop[0]) {
      firstDropTO = 1;
    }
    if (history[to[i]].seqno == renoDrop[1]) {
      secondDropTO = 1;
    }
  }

  renoversion = Uncategorized;

  // NewReno: Characterized by:
  // - Fast Retransmit for packet 12 (e.g. no RTOs)
  // - No additional Fast Retransmits or RTO
  // - No Unnecesary retransmission of packet 16
  if (numTO == 0) {
    if (history[rxmt[0].hist_index].seqno == renoDrop[0]) { // pkt 12th retransmitted
      if (history[rxmt[1].hist_index].seqno == renoDrop[1]) { // pkt 15th retransmitted
	if (pkt16_found == 0) {
	  count++; 
	  renoversion = NewReno;
	}
      }
    }
  }

  // RenoPlus - Characterized by: 
  // - No RTOs for packets 12th or 15th
  // - Transmission of additional packets "off-the top" 
  //   between the retransmissions of packets 13th and 15th
  // - No unnecsarry retransmissions
  if ((renoversion == Uncategorized) &&
      (firstDropTO == 0) &&
      (secondDropTO == 0) &&
      ((rxmt[1].hist_index - rxmt[0].hist_index) > 2) &&
      (history[rxmt[0].hist_index].seqno == renoDrop[0]) &&
      (history[rxmt[1].hist_index].seqno == renoDrop[1]) &&
      (pkt16_found == 0)) {
    count ++; 
    renoversion = RenoPlus;
  }

  // Reno - characterized by:
  // - Fast retransmit of packet 12th
  // - Retransmission TO for packet 15th
  // - No unnecessary retransmission of packet 16th
  if (renoversion == Uncategorized) {
    if ((firstDropTO == 0) && (secondDropTO == 1)) {
      if (pkt16_found == 0) {
	count++; 
	renoversion = Reno;
      }
    }
  }

  // Tahoe - Characterized by:
  // - No RTO before the reatransmission of packet 12th
  // - Unnecessary retransmission for packet 16th
  if ((renoversion == Uncategorized) &&
      (numRxmt > 2) &&
      (firstDropTO == 0) &&
      (pkt13_found == 0) &&
      (pkt16_found == 1)) {
    count++; 
    renoversion = Tahoe;
  }

  // TahoeNoFR- Characterized by:
  // - RTO for the reatransmission of packet 12th
  // - Unnecessary retransmission for packet 16th
  if ((renoversion == Uncategorized) &&
      (firstDropTO == 1) &&
      (pkt13_found == 0) &&
      (pkt16_found == 1)) {
    count++; 
    renoversion = TahoeNoFR;
  }

  // AggresiveFastRetransmit - Characterized by:
  // - No RTOs
  // - More than 3 retransmissions
  // - Unnessary retransmission of packet 13 and 16
  if ((renoversion == Uncategorized) &&
      (firstDropTO == 0) &&
      (secondDropTO == 0) &&
      (numRxmt > 3) &&
      (pkt13_found == 1) &&
      (pkt16_found == 1)) {
    count++; 
    renoversion = AggresiveFastRetransmit;
  }

  // AggresiveTahoeNoFR - Characterized by:
  // - RTO for packet 12th
  // - No RTO for packet 15th
  // - More than 2 retransmissions
  // - Unnessary retransmission of packet 13
  if ((renoversion == Uncategorized) &&
      (firstDropTO == 1) &&
      (secondDropTO == 0) &&
      (numRxmt > 2) &&
      (pkt13_found == 1)) {
    count++; 
    renoversion = AggresiveTahoeNoFR;
  }

  // If sender used a smaller MSS, igonre result
  //if (session.sndmss < session.mss) {
  //  printf("Sender session MSS (%d) is smaller than TBIT requested MSS (%d) ==> Ignore result...\n",
  //	   session.sndmss, 
  //   session.mss);
  //session.ignore_result = 1;
  //}

  printf("pkt13found: %d pkt16found: %d TO1: %d TO2: %d\n", pkt13_found, pkt16_found, firstDropTO, secondDropTO);

  printf("#### rx=%d to=%d version=%s reord=%d drops=%d ignore=%d clnt.mss=%d srv.mss=%d\n", 
	 numRxmt, 
	 numTO, 
	 renoVersionNames[renoversion], 
	 session.num_reordered,
	 session.num_unwanted_drops,
	 session.ignore_result,
	 session.mss,
	 session.sndmss);

}



