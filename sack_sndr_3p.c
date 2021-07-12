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
#include "sack_rcvr.h"
#include "sack_sndr_3p.h"

#define MAXRXMT 20  
#define SB 20 

extern struct TcpSession session;
extern struct History history[];

static uint32 sackDrop[3]; 
static int droppedForSackTest; 

void SackSndr3PTest (uint32 sourceIpAddress, uint16 sourcePort, uint32 targetIpAddress, uint16 targetPort, int mss) 
{
  int optlen; 
  char *opt; 

  optlen = 8;
  if ((opt=(char *)calloc(sizeof(uint8), optlen)) == NULL)	{
    printf("ERROR: Could not allocate opt.\nRETURN CODE: %d\n", ERR_MEM_ALLOC);
    Quit(ERR_MEM_ALLOC);
  }
  /* mss option */
  opt[0] = (uint8)TCPOPT_MAXSEG ; 
  opt[1] = (uint8)TCPOLEN_MAXSEG ; 
  *((uint16 *)((char *)opt+2)) = htons(mss);

  /* align 4-byte boundries */
  opt[4] = (uint8)TCPOPT_NOP ;
  opt[5] = (uint8)TCPOPT_NOP ;

  /* sack option */
  opt[6] = (uint8)TCPOPT_SACK_PERMITTED ;
  opt[7] = (uint8)TCPOLEN_SACK_PERMITTED ;

  if (EstablishSession(sourceIpAddress,
		       sourcePort,
		       targetIpAddress,
		       targetPort,
		       0,    /* ip_opt len */
		       NULL, /* ip_opt pointer */
		       mss,
		       optlen,
		       opt,
		       16,
		       10000,
		       0,
		       0) == 0) {

    printf("ERROR: Couldn't establish session\nRETURN CODE: %d\n", 
	   NO_SESSION_ESTABLISH);
    Quit(NO_SESSION_ESTABLISH);

  }
	
  if (!isSack ()) {
    printf ("ERROR: remote host does not support sack\nRETURN CODE: %d\n", NO_SACK);
    Quit(NO_SACK);
  }

  SendRequest(session.filename, (void *)NewSack3PData); 
  rcvData (NewSack3PData);

}



void NewSack3PData (struct IPPacket *p) 
{
  uint32 src;
  uint32 dst;
  uint16 sport;
  uint16 dport;
  uint32 seq;
  uint32 ack;
  uint8  flags;
  uint16 win;
  uint16 urp;
  uint16 datalen;
  uint16 ip_optlen;
  uint16 optlen;

  char  *dataptr ;
  int i,l; 
  struct IPPacket *ackpkt ; 
  int dropForSackTest = 0 ; 
  char *opt; 
  int tcp_optlen;

  // Keep these to avoid drop a retransmitted packet
  static int packet_15_dropped = 0;
  static int packet_17_dropped = 0;
  static int packet_19_dropped = 0;

  // Keep these to avoid counting retransmissions 
  // for one of our dropped packets more than once
  static int packet_15_seen = 0;
  static int packet_17_seen = 0;
  static int packet_19_seen = 0;

  int packet_number;

  // Keep track of seqno vs. pkt_num received
  static int *rcvd_pkt_num;

  rcvd_pkt_num = calloc(session.maxpkts, sizeof(int));
  assert(rcvd_pkt_num != NULL);
  
  opt = NULL;
  ReadIPPacket (p, &src, &dst, &sport, &dport, &seq, &ack, &flags, &win,
		&urp, &datalen, &ip_optlen, &optlen);

  if (session.debug) {
    printf ("datalen = %d\n\n", (int)datalen);
    if (datalen > 0) {
      dataptr = (char *)p + (int)sizeof(struct IPPacket) + (int)optlen ;		
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

  if (datalen > session.sndmss) {
    session.sndmss = datalen;
  }

  if ((seq + datalen - session.irs) > session.mss * session.maxpkts) {
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
    packet_number = (int)ceil((float)(seq - session.irs) /(float)session.sndmss);

    if (rcvd_pkt_num[packet_number] != 0 && rcvd_pkt_num[packet_number] != (seq - session.irs)) {
      printf("Inconsistent packet numbering - smaller MSS?...\n");
      session.ignore_result = 1;
    }else {
      rcvd_pkt_num[packet_number] = seq - session.irs;
    }

    if (session.totDataPktsRcvd >= session.maxpkts) {
      if (session.totOutofSeq < 3) {
	printf("ERROR: Not Enough Packets to complete test...\nRETURN CODE: %d\n", NOT_ENOUGH_PKTS);
	Quit(NOT_ENOUGH_PKTS);
      } else {
	NewSack3PCheck() ;
	Quit(SUCCESS); 
      }
    }
  }
  
  if(session.maxseqseen <= seq + datalen - 1) {

    session.maxseqseen = seq + datalen - 1; 

  } else {

    if (datalen > 0) {

      printf ("##### out-of-seq packet %f %d %d \n", 
	      GetTime() - session.epochTime, 
	      seq-session.irs, 
	      seq-session.irs + datalen);

      // Check if this packet represents a packet drop or just a reodering
      if (reordered(p) != 1) {
	if (seq != sackDrop[0] && seq != sackDrop[1] && seq != sackDrop[2]) {
	  session.num_unwanted_drops += 1;
	  if (session.verbose) {
	    printf ("possible unwanted packet drop - session flagged...\n");
	  }
	}
      }

      // Count as out-of-sequence packet iff it was dropped by us
      // and we have not received a previous retransmission for it
      for (l = 0; l < droppedForSackTest; l++) {
	 if (sackDrop[l] == seq) {
	   if ((packet_number == 15) && (packet_15_seen == 0)) {
	     packet_15_seen = 1;
	     session.totOutofSeq++;
	   }
	   if ((packet_number == 17) && (packet_17_seen == 0)) {
	     packet_17_seen = 1;
	     session.totOutofSeq++;
	   }
	   if ((packet_number == 19) && (packet_19_seen == 0)) {
	     packet_19_seen = 1;
	     session.totOutofSeq++;
	   }
	   break;
	 }
      }
    }
  }
  
  /*
   * drop packets for sack test?  
   */

  if ((packet_number == 15) && (packet_15_dropped == 0)) {
    packet_15_dropped = 1;
    sackDrop[droppedForSackTest++] = seq ;	
    dropForSackTest = 1;
    printf ("##### droppacket %f %d %d %d\n", 
	    GetTime() - session.epochTime, 
	    seq - session.irs, 
	    seq - session.irs + datalen,
	    packet_number);
  }   

  if ((packet_number == 17) && (packet_17_dropped == 0)) {
    packet_17_dropped = 1;
    sackDrop[droppedForSackTest++] = seq ;	
    dropForSackTest = 1;
    printf ("##### droppacket %f %d %d %d\n", 
	    GetTime() - session.epochTime, 
	    seq - session.irs, 
	    seq - session.irs + datalen,
	    packet_number);
  }   

  if ((packet_number == 19) && (packet_19_dropped == 0)) {
    packet_19_dropped = 1;
    sackDrop[droppedForSackTest++] = seq ;	
    dropForSackTest = 1;
    printf ("##### droppacket %f %d %d %d\n", 
	    GetTime() - session.epochTime, 
	    seq - session.irs, 
	    seq - session.irs + datalen,
	    packet_number);
  }   

  if (session.verbose && dropForSackTest == 1) {

    printf ("d %f %d %d %d %d\n", 
	    GetTime() - session.epochTime, 
	    seq - session.irs, 
	    seq - session.irs + datalen,
	    session.totDataPktsRcvd,
	    packet_number);
  }

  if (datalen > 0 && session.verbose && dropForSackTest == 0) {

    printf ("r %f %d %d %d %d\n", 
	    GetTime() - session.epochTime, 
	    seq - session.irs, 
	    seq - session.irs + datalen,
	    session.totDataPktsRcvd,
	    (seq - session.irs) / session.mss);
  }

  if (session.totOutofSeq == 3) {
    NewSack3PCheck();
    Quit(SUCCESS);
  }


  /* from TCP/IP vol. 2, p 808 */
  if (session.debug) {
    printf ("dlen = %d sack = %d seq = %u rcv_nxt = %u rcv_wnd = %u\n", datalen, dropForSackTest, 
	    seq, session.rcv_nxt, session.rcv_wnd);
  }
  if ((datalen > 0) && 
      (dropForSackTest == 0) &&
      (session.rcv_nxt <= seq) && 
      (seq < (session.rcv_nxt + session.rcv_wnd))  &&
      (session.rcv_nxt <= (seq + datalen)) && 
      ((seq + datalen - 1) < (session.rcv_nxt + session.rcv_wnd))) {

    int start = seq - session.irs ; 
    int end = start + datalen ; 

    if (session.debug) {
      printf ("rcvd = %d - %d\n", start, end);
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

  if (flags & TCPFLAGS_FIN) {

    if (session.totOutofSeq == 3) {

      NewSack3PCheck () ;
      Quit(SUCCESS); 

    }else {

      printf("ERROR: Not Enough Packets to complete test...\nRETURN CODE: %d\n", NOT_ENOUGH_PKTS);
      Quit(NOT_ENOUGH_PKTS);

    }
  }
  
  if ((datalen > 0) && (dropForSackTest == 0)) {
	  
    if (session.debug) { 
      printf ("sending ack\n");
    }
	  
    busy_wait(PLOTDIFF);
    tcp_optlen = 0;
	
    // **** Comment this to test without using SACK blocks ***** 
    if (session.maxseqseen > session.rcv_nxt) {
      opt = FillSack3POpt(&tcp_optlen);
     }


    /* Allocate IP ACK Packet */
    ackpkt = AllocateIPPacket(0, tcp_optlen, 0, "SackSndr3P (ACK)");


    /* fill in the options */
    if (tcp_optlen > 0) {
      //memcpy((char *)ackpkt+sizeof(struct IPPacket), opt, tcp_optlen);
      memcpy((char *)ackpkt->tcp + sizeof(struct TcpHeader), opt, tcp_optlen);
    }

    SendSessionPacket(ackpkt, 
		      sizeof(struct IpHeader) + sizeof(struct TcpHeader) + tcp_optlen,
		      TCPFLAGS_ACK, 
		      0,          /* ip options len */
		      tcp_optlen, /* tcp options len */
		      0);

    free(ackpkt->ip);
    free(ackpkt->tcp);
    free(ackpkt);

    free(opt);

    if (session.verbose) {
      printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt-session.irs);
    }
  }
}

char *FillSack3POpt(int *optlen) 
{
  uint32 sb[2 * SB];
  int start, end;
  int inhole = 0;
  char *opt;
  int edges = 0; 

  start = session.maxseqseen - session.irs;
  end = start;
  while (start >= 0) {
    switch (session.dataRcvd[start]) {
    case 1: 
      if (inhole) {
	end = start;
	inhole = 0;
      }
      break;
    case 0: 
      if (!inhole) {
	inhole = 1;
	if (edges == 2*SB) {
	  printf ("Too many holes\n");
	  Quit (TOO_MANY_HOLES);
	}
	sb[edges] = start + 1 + session.irs;
	sb[edges] = htonl(sb[edges]);
	edges++;
	sb[edges] = end + 1 + session.irs;
	sb[edges] = htonl(sb[edges]);
	edges++;
      }
      break;
    default: 
      printf ("Error in sack block calulcation\n");
      Quit(ERR_IN_SB_CALC);
      break;
    }
    start --;
  }
	
  *optlen = 4+sizeof(uint32)*edges; 
  if ((opt=(char *)calloc(sizeof(uint8), *optlen)) == NULL)	{
    printf("ERROR: Could not allocate opt.\nRETURN CODE: %d\n",ERR_MEM_ALLOC);
    Quit(ERR_MEM_ALLOC);
  }
  opt[0] = (uint8)TCPOPT_SACK ; 
  opt[1] = (uint8)(2+4*edges) ;
  memcpy(opt+2, sb, edges*sizeof(uint32));	
  opt[*optlen-2] = (uint8)TCPOPT_NOP ;
  opt[*optlen-1] = (uint8)TCPOPT_NOP ;
  return opt;
}



void NewSack3PCheck () 
{

  int sack = 1;	
  int i, j;	
  double start = 0; 
  double end = 999999999999999.0;
  uint32 rxmt[MAXRXMT];
  int numRxmt = 0;

  int order = 1;
  int sackDrop_0_Seen = 0;
  int sackDrop_1_Seen = 0;
  int sackDrop_2_Seen = 0;
  int packet_18_ret_seen = 0;
  // Keep track of retransmission times
  double sackDrop_0_ret_time = 0.0;
  double sackDrop_1_ret_time = 0.0;
  double sackDrop_2_ret_time = 0.0;
  double packet_18_ret_time = 0.0;
  int sackDrop_0_pos = 0;
  int sackDrop_1_pos = 0;
  int sackDrop_2_pos = 0;
  int packet_18_pos = 0;
  int sackDrop_1_dlen = 0;

  float time_0, time_1, time_2;
  float diff01, diff12;

  for (i = 1; ((i < session.hsz) && (sack == 1)); i++) {

    if ((history[i].type == RCVD) && (history[i].dlen > 0)) {

      for (j = 0 ; j < i - 1 ; j++) {

	if ( (history[j].type == RCVD) && (history[j].dlen > 0) &&
	     (history[j].seqno <= history[i].seqno) &&
	     (history[j].nextbyte > history[i].seqno)) {

	  // If the first retranmission observed is not for one of the
	  // packets we dropped, then ignore it

	  if ((numRxmt == 0) && \
	      ((history[i].seqno != sackDrop[0]) &&
	       (history[i].seqno != sackDrop[1]) &&
	       (history[i].seqno != sackDrop[2]))) {
	    continue;
	  }

	  rxmt[numRxmt++] = i; 

	  if ((numRxmt == 1) && \
	      ((history[i].seqno == sackDrop[0]) ||
	       (history[i].seqno == sackDrop[1]) ||
	       (history[i].seqno == sackDrop[2]))) {
	    start = history[i].timestamp;
	  }

	  if (history[i].seqno == sackDrop[0]) {
	    sackDrop_0_Seen = 1;
	    sackDrop_0_ret_time = history[i].timestamp;
	    sackDrop_0_pos = order++;
	  }

	  if (history[i].seqno == sackDrop[1]) {
	    sackDrop_1_Seen = 1;
	    sackDrop_1_ret_time = history[i].timestamp;
	    sackDrop_1_pos = order++;
	    sackDrop_1_dlen = history[i].dlen;
	  }

	  if (history[i].seqno == sackDrop[2]) {
	    sackDrop_2_Seen = 1;
	    sackDrop_2_ret_time = history[i].timestamp;
	    sackDrop_2_pos = order++;
	  }
	  
	  if (history[i].seqno == sackDrop[1] + sackDrop_1_dlen) {
	    packet_18_ret_seen = 1;
	    packet_18_ret_time = history[i].timestamp;
	    packet_18_pos  = order++;
	  }
	  
	  if ((numRxmt >= 3) && \
	      (sackDrop_0_Seen) &&
	      (sackDrop_1_Seen) &&
	      (sackDrop_2_Seen)) {
	    end = history[i].timestamp;
	    sack = 0; // exit outer loop
	    break;
	  }
	}
      }
    }
  }

  printf("numrxmt: %d\n", numRxmt);
  printf("session.rtt: %f\n", session.rtt);
  printf("pkt_18_ret_seen: %d\n", packet_18_ret_seen);
  printf("POS 15: %d\n", sackDrop_0_pos);
  printf("POS 17: %d\n", sackDrop_1_pos);
  printf("POS 19: %d\n", sackDrop_2_pos);
  printf("RCV 15: %f\n", sackDrop_0_ret_time);
  diff01 = abs(sackDrop_1_ret_time - sackDrop_0_ret_time);
  printf("RCV 17: %f diff: %f\n", sackDrop_1_ret_time, diff01);
  diff12 = abs(sackDrop_2_ret_time - sackDrop_1_ret_time);
  printf("RCV 19: %f diff: %f\n", sackDrop_2_ret_time, diff12);

  sack = 1;

  // NewReno: We should observe a retransmission behavior purely
  // based on cummulative acks. Observe the retransmission of packet
  // 15, ack up to packet 16, observe, at least one "minimun" RTT
  // later, the retransmission of packet 17, ack up to pkt 18 it and then,
  // again at least one "minimum" RTT later, we observe the
  // retransmission of packet 19.

  if ((sackDrop_0_pos < sackDrop_1_pos) &&
      (sackDrop_1_pos < sackDrop_2_pos)) {
    
    if ((sackDrop_1_ret_time - sackDrop_0_ret_time >= session.rtt) &&
	(sackDrop_2_ret_time - sackDrop_1_ret_time >= session.rtt) &&
	(packet_18_ret_seen == 0)) {

      if (session.verbose) {
	printf("### NewReno behavior ");
	if (session.num_unwanted_drops > 0) {
	  printf("- session experienced unwanted drops!\n");
	}else {
	  printf("\n");
	}	
      }
      sack = 2; // NewReno
      printf ("#### sack = %d drops = %d ignore = %d\n", 
	      sack, 
	      session.num_unwanted_drops,
	      session.ignore_result);	
      return;

    }
  }

  // 2. Semi-sack: observe partial SACK behavior. 
  // The server seems to make proper use of
  // SACK blocks but fail to transmit either the first or
  // the last block in time. 
  // Two of the retransmissions arrive within a "minimum" RTT 
  // while the other arrives much later (e.g > 1 RTT)

  if ((sack == 1) && (sackDrop_0_ret_time > sackDrop_1_ret_time)) {

    if (sackDrop_0_ret_time > sackDrop_2_ret_time) {

      time_2 = sackDrop_0_ret_time;

      if (sackDrop_1_ret_time > sackDrop_2_ret_time) {

	time_0 = sackDrop_2_ret_time;
	time_1 = sackDrop_1_ret_time;

      }else {

	time_0 = sackDrop_1_ret_time;
	time_1 = sackDrop_2_ret_time;
      }

    }else {

      time_2 = sackDrop_2_ret_time;
      time_1 = sackDrop_0_ret_time;
      time_0 = sackDrop_1_ret_time;
    }

  }else {

    if (sackDrop_1_ret_time > sackDrop_2_ret_time) {

      time_2 = sackDrop_1_ret_time;
      if (sackDrop_2_ret_time > sackDrop_0_ret_time) {
	time_0 = sackDrop_0_ret_time;
	time_1 = sackDrop_2_ret_time;
      }else {
	time_0 = sackDrop_2_ret_time;
	time_1 = sackDrop_0_ret_time;
      }
    }else {
      time_2 = sackDrop_2_ret_time;
      time_1 = sackDrop_1_ret_time;
      time_0 = sackDrop_0_ret_time;
    }
  }     

  diff01 = time_1 - time_0;
  diff12 = time_2 - time_1;

  if ((((diff01 <= session.rtt) && (diff12 > session.rtt)) ||
      ((diff12 <= session.rtt) && (diff01 > session.rtt))) &&
      (packet_18_ret_seen == 0)) {

    if (session.verbose) {
      printf("### Semi-sack behavior ");
      if (session.num_unwanted_drops > 0) {
	printf("- session experienced unwanted drops!\n");
      }else {
	printf("\n");
      }
    }
    sack = 3;
    printf ("#### sack = %d drops = %d ignore = %d\n", 
	    sack, 
	    session.num_unwanted_drops,
	    session.ignore_result);	
    return;							      

  }

  // 3. TahoeNoFR: packet 15 is retransmitted and at least one RTT
  // later packets 17 and 18 are retransmitted. TBIT receives the
  // retransmission for packet 15, sends the cummulative ack for packet
  // 16, receives in response the retransmission for packets 17 and 18.

  if ((sack == 1) && (sackDrop_0_pos < sackDrop_1_pos)) { 

    // difference between arrival of retransmission for packet 15 
    // and retransmission for packet 17
    diff01 = sackDrop_1_ret_time - sackDrop_0_ret_time;

    if ((diff01 >= session.rtt) && (packet_18_ret_seen == 1)) {

      if (session.verbose) {
	printf("### TahoeNoFR behavior\n");
      }

      sack = 4;
      printf ("#### sack = %d drops = %d ignore = %d\n", 
	      sack, 
	      session.num_unwanted_drops,
	      session.ignore_result);	
      return;	

    }						            
  }

  if ((sack == 1) && ((end - start) > 2 * session.rtt)) {
    if (session.verbose) {
      printf("### Delayed retransmission\n");
    }
    sack = 0;
  }

  if (session.verbose) {
    printf ("#### %f %f %d\n", (end - start), 2 * session.rtt, numRxmt);
  }

  printf ("#### sack = %d drops = %d ignore = %d\n", 
	  sack, 
	  session.num_unwanted_drops,
	  session.ignore_result);	

}
