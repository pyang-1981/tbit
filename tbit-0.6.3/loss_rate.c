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
#include "loss_rate.h"

#define MAXRXMT 100000  
#define MAXTO 100000  

extern struct TcpSession session;
extern struct History history[];

void LossRateTest(uint32 sourceIpAddress, uint16 sourcePort, uint32 targetIpAddress, uint16 targetPort, int mss) 
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
  *((uint16 *)((char *)opt+2)) = htons(mss);

  if (EstablishSession(sourceIpAddress,
		       sourcePort,
		       targetIpAddress,
		       targetPort,
		       0, /* ip_opt len */
		       NULL, /* ip_opt pointer */
		       mss,
		       optlen,
		       opt,
		       10,
		       //8000/mss,
		       100000,
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\nRETURN CODE: %d\n", NO_SESSION_ESTABLISH);
    Quit(NO_SESSION_ESTABLISH);
  }
  SendRequest(session.filename, (void *)LossRateAckData); 
  rcvData (LossRateAckData);
}


void LossRateAckData (struct IPPacket *p) 
{

  uint32 seq = history[session.hsz - 1].seqno;
  uint8  fin = history[session.hsz - 1].fin;
  uint16 datalen = history[session.hsz - 1].dlen;
  char  *dataptr = history[session.hsz - 1].data;
  int i; 
  struct IPPacket ackpkt; 
  int dropForLossRateTest = 0; 
  int packet_number;

  double loss_prob = 0.0;

  // Keep track of seqno vs. pkt_num received
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

  // keep track of sender's  maximum segment size
  if (datalen > session.sndmss) {
    session.sndmss = datalen;
  }

  if ((seq-session.irs + datalen) > session.mss * session.maxpkts) {
    printf ("ERROR: buffer overflow: %u %d %u %d %d\nRETURN CODE: %d\n", 
	    seq, datalen, session.irs, seq+datalen-session.irs, session.mss*session.maxpkts,BUFFER_OVERFLOW);
    Quit(BUFFER_OVERFLOW); 
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

    session.totDataPktsRcvd++ ;
    packet_number = (seq - session.irs) / session.mss;

    if ((packet_number != 0) && (rcvd_pkt_num[packet_number] != 0) && (rcvd_pkt_num[packet_number] != (seq - session.irs))) {
      printf("Inconsistent packet numbering - smaller MSS? ==> Ignore result...\n");
      session.ignore_result = 1;
    }else {
      rcvd_pkt_num[packet_number] = seq - session.irs;
    }
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
      /* For this test all drops are "unwanted" */
      if (reordered(p) != 1) {
	session.num_unwanted_drops += 1;
      }
    }
  }

  /* Record number of each received packet */
  history[session.hsz - 1].pkt_num = packet_number;

  /*
   * drop packets for loss rate test? 
   *
   */

  loss_prob = drand48();

  if (loss_prob < session.loss_rate) {
    dropForLossRateTest = 1;
    printf ("##### droppacket %f %d %d\n", 
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

  if (datalen > 0 && session.verbose && dropForLossRateTest == 0) {
    
    printf ("r %f %d %d %d %d\n", 
	    GetTime() - session.epochTime, 
	    seq - session.irs, 
	    seq - session.irs + datalen,
	    session.totDataPktsRcvd,
	    packet_number);
  }

  if (session.debug) {
    printf ("dlen=%d reno=%d seq=%u rcv_nxt=%u rcv_wnd=%u\n", datalen, dropForLossRateTest, 
	    seq, session.rcv_nxt, session.rcv_wnd);
  }

  /* If received packet does not have to be dropped and the data
   * received falls inside the current congestion window, update state
   * and check if we have enough information already to identify the server
   */
  if ((datalen > 0) && 
      (dropForLossRateTest == 0) &&
      (session.rcv_nxt <= seq) && (seq < (session.rcv_nxt + session.rcv_wnd))  &&
      (session.rcv_nxt <= (seq + datalen)) && ((seq + datalen - 1) < (session.rcv_nxt + session.rcv_wnd))) {
    
    int start = seq - session.irs ; 
    int end = start + datalen ; 
    if (session.debug) {
      printf ("rcved = %d-%d\n", start, end);
    }

    for (i = start ; i < end ; i++) {
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
  }

  if (fin) {

    SummarizeStatistics();
    Quit(SUCCESS); 

  }else {

    if ((datalen > 0) && (dropForLossRateTest == 0)) {

      if (session.debug) { 
	printf ("sending ack\n");
      }

      busy_wait(PLOTDIFF);

      /* If the one-way propagation delay was specified, 
       * delay acking of packets
       */

      if (session.verbose && session.prop_delay > 0.0) {
      	printf("Delaying ACK...\n");
      }

      busy_wait(session.prop_delay);

      SendSessionPacket (&ackpkt, 
			 sizeof(struct IpHeader) + sizeof(struct TcpHeader),
			 TCPFLAGS_ACK, 
			 0,
			 0, 
			 0);

      if (session.verbose) {
	printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt - session.irs);
      }

    }
  }
}

void SummarizeStatistics() {

  struct LossRateRxmt rxmt[MAXRXMT];
  int to[MAXTO] ; 
  int i, j ; 
  int numRxmt = 0, numTO = 0 ;	

  printf("Totdata = %d\n", session.rcv_nxt - session.irs);
  printf("session.rtt = %f\n", session.rtt);
  
  /* Count the number of retransmissions */
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
    
  /* Count the number and values of the RTO */
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

}
