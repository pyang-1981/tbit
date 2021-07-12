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
#include "capture.h"
#include "support.h"
#include "tbit.h"
#include "history.h"
#include "dsack.h"

extern struct TcpSession session;
extern struct History history[];

void DuplicateSackTest(uint32 sourceAddress, uint16 sourcePort, uint32 targetAddress, uint16 targetPort, int mss) 
{
  int optlen ; 
  char *opt	; 
  
  optlen = 8 ;
  if ((opt = (char *)calloc(sizeof(uint8), optlen)) == NULL)	{
    printf("ERROR: Could not allocate opt\nRETURN CODE: %d", ERR_MEM_ALLOC);
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
  
  if (EstablishSession(sourceAddress,
		       sourcePort,
		       targetAddress,
		       targetPort,
		       0,    /* ip_opt len */
		       NULL, /* ip_opt pointer */
		       mss,
		       optlen,
		       opt,
		       5,
		       100,
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\nRETURN CODE: %d", NO_SESSION_ESTABLISH);
    Quit(NO_SESSION_ESTABLISH);
  }

  if (!DSACK_isSack ()) {
    printf("ERROR: NOT SACK-CAPABLE SERVER\nRETURN CODE: %d\n", NO_SACK);
    Quit(NO_SACK);
  }

  DSACK_SendBrokenRequest();
  DSACK_checkSackRcvr();

  free(opt);

  Quit(SUCCESS);

}

int DSACK_isSack () {

  int i, j; 

  for (i = 1; i < session.hsz; i++) {

    if ((history[i].type == RCVD) && (history[i].ack) && (history[i].syn)) {

      j = 0 ;

      while (j < history[i].optlen) {

	switch ((unsigned char)history[i].opt[j]) {

	case TCPOPT_EOL:
	  j = j + TCPOLEN_EOL;
	  break; 

	case TCPOPT_NOP:
	  j = j + TCPOLEN_NOP ;
	  break;

	case TCPOPT_SACK_PERMITTED:
	  return 1;
	  break ; 

	default: 

	  if ((uint8)history[i].opt[j + 1] > 0) {
	    j = j + (uint8)history[i].opt[j + 1] ;
	  } 
	  else {
	    printf("RETURN CODE: %d\n", BAD_OPT_LEN);
	    Quit(BAD_OPT_LEN); 
	  }
	  break ;

	}
      } 
    }
  }

  return 0;

}

void DSACK_SendBrokenRequest() 
{

  /* In this case the broken request is sent in one of two ways:
   * 1) Send segments 1, 3, 3
   * 2) Send segments 1, 3, 1
   */

  struct IPPacket *p, *datapkt;
  struct PacketInfo pi;
  char *read_packet;
  int i ;
  uint16 lastSeqSent = session.snd_nxt; 
  double startTime;
  char *dataptr ; 
  char data[MAXREQUESTLEN];
  int datalen;
  int second_pkt_1_snt = 0;
  
  p = NULL; 
  datapkt = NULL;
  
  /*
   * Send data packets 1 and 3. 
   * The ack for 1 should have no sack blocks. 
   * The ack for 3 should have sack blocks indicating a hole at 2. 
   * Each packet will be 1 byte long.  
   * Wait for 2 seconds after each packet is sent to receive an ack,
   * otherwise, quit.
   */
  
  datalen = PrepareRequest(data, session.filename);
  printf("SESSION NXT: %d\n", session.snd_nxt - session.iss);      
  for (i = 0; i < 14 ; i++) {

    datapkt = AllocateIPPacket(0, 0, 1, "SackRcvr (DataPkt)");

    dataptr = (char *)datapkt->tcp + sizeof(struct TcpHeader);
    memcpy((void *)dataptr, (void *)data + i, 1);

    if (session.verbose) {
      printf ("s %f %d\n", GetTime() - session.epochTime, session.snd_nxt);
    }

    SendSessionPacket(datapkt, 
		      sizeof(struct IpHeader) + sizeof(struct TcpHeader) + 1, 
		      TCPFLAGS_PSH | TCPFLAGS_ACK, 
		      0, 
		      0, 
		      0);

    startTime = GetTime();

    StorePacket(datapkt);

    while (1) {

      /* Check if we have received any packets */
      if ((read_packet =(char *)CaptureGetPacket(&pi)) != NULL) {

	p = (struct IPPacket *)FindHeaderBoundaries(read_packet);

	/*
	 * packet that we sent?
	 */
	if (INSESSION(p,session.src,session.sport,session.dst,session.dport) &&
	    (p->tcp->tcp_flags == (TCPFLAGS_PSH | TCPFLAGS_ACK)) &&
	    (ntohl(p->tcp->tcp_seq) > lastSeqSent) &&
	    (ntohl(p->tcp->tcp_ack) <= session.rcv_nxt)) {

	  lastSeqSent = ntohl(p->tcp->tcp_seq);
	  if (session.debug) {
	    printf("saw the packet we sent: xmit %d\n", i);
	    PrintTcpPacket(p);
	  }

	  //StorePacket(p);
	  session.totSeenSent++ ;
	  free(p);
	  continue ;

	} 

	/*
	 * from them? 
	 */ 
	if (INSESSION(p,session.dst,session.dport,session.src,session.sport) &&
	    (p->tcp->tcp_flags & TCPFLAGS_ACK) &&
	    (ntohl(p->tcp->tcp_ack) >= session.snd_una)) {

	  if (ntohl(p->tcp->tcp_ack) > session.snd_una) {
	    session.snd_una  = ntohl(p->tcp->tcp_ack);
	  }

	  if (session.debug) {
	    PrintTcpPacket(p);
	  }

	  StorePacket(p);
	  session.totRcvd++;
	  free(p);
	  break;

	}

      }

      if (GetTime() - startTime >= REXMITDELAY) {
	printf ("ERROR: no response\nRETURN CODE: %d", NO_CONNECTION);
	Quit(NO_CONNECTION);
      }

    }

    free(datapkt->ip);
    free(datapkt->tcp);
    free(datapkt);

    /* Now, bump up the snd_nxt to create a false loss and skip an
     * iteration. Is skipping iteration necessary?
     */


    switch(session.snd_nxt - session.iss) {
    case 1:

      if (second_pkt_1_snt == 0) {

	session.snd_nxt += 2; /* send segment 3 next */
	i += 1;

      }else {

	session.snd_nxt += + 3;; /* send segment 3 next */
	i += 3;

      }
      //printf("SESSION NXT: %d\n", session.snd_nxt - session.iss);      
      break;

    case 3:
      if (second_pkt_1_snt == 0) {
	second_pkt_1_snt = 1;
	session.snd_nxt = session.iss + 1;
	i = -1; /* rewind i by one to send same 1st segment again */
	//printf("SESSION NXT: %d\n", session.snd_nxt - session.iss);      
	break;
      }

    default:
      session.snd_nxt += 1; /* continue sending subsequent requests */
      //printf("SESSION NXT: %d\n", session.snd_nxt - session.iss);      
      i += 1;
    }

  }

}

void DSACK_checkSackRcvr() 
{
  /*
   * Check if there is a "normal" ack for the first packet and a
   * "sack" for the second packet.  The sack for second packet should
   * have appropriate sack blocks.
   */

  int i, j;
  int count = 0;
  uint32 sb[MAXSB];
  int numsb = -1; 

  for (i = 0 ; i < session.hsz; i++) {

    if ((history[i].type == RCVD) && (history[i].ack == 1) && 
	(history[i].syn == 0) && (history[i].dlen == 0)) {

      count++; 
      if (count == 1) {
	if (!(history[i].ackno - session.iss) == 2) {
	  /* The SYN packet consumes one sequence number, and the
	     first byte of the request packet consumes another
	     one. Therefore, the ackno for the first ACK should be
	     session.iss + 1, and therefore the above subtraction
	     should be equal to 2 */
	  printf ("RESULT: IMPROPER BEHAVIOR FIRST ACK\n");
	  Quit(SUCCESS);
	}
      }

      if (count > 1) {
	
	if (history[i].optlen == 0) {
	  printf ("RESULT: NO SACK BLOCK IN ACK %d %d\n", i, session.hsz);
	  Quit(SUCCESS);
	}

	j = 0;
	while (j < history[i].optlen) {
	  
	  switch ((unsigned char)history[i].opt[j]) {

	  case TCPOPT_EOL:
	    j = j + TCPOLEN_EOL;
	    break;

	  case TCPOPT_NOP:
	    j = j + TCPOLEN_NOP ;
	    break;

	  case TCPOPT_SACK:

	    DSACK_GetSB(history[i].opt, history[i].optlen, j, sb, &numsb);

	    if (count == 3) {

	      if (numsb < 2) {
		printf ("RESULT: NO DUPLICATE SACK BLOCK in ACK 3\n");
		Quit(SUCCESS);
	      }
	      
	      if ((sb[0] != session.iss + 1|| sb[1] != session.iss + 2) ||
		  (sb[2] != session.iss + 3 || sb[3] != session.iss + 4)) {
		printf ("RESULT: WRONG DUPLICATE SACK BLOCK in ACK 3\n");
		Quit(SUCCESS);
	      }else {
		printf ("RESULT: DSACK-CAPABLE SERVER\n");
		Quit(SUCCESS);
	      }
	    }

	    j = j + (uint8)history[i].opt[j + 1] ;
	    break;

	  default: 

	    if ((uint8)history[i].opt[j + 1] > 0) {   // len byte > 0

	      j = j + (uint8)history[i].opt[j + 1] ;  // advance j index

	    }else {
	      printf("RETURN CODE: %d\n", BAD_OPT_LEN);
	      Quit (BAD_OPT_LEN);
	    }
	    break;

	  }
	}
      }
    }
  }

  if (count != 7) {
    printf ("RESULT: ERROR IN SACK SEQUENCE\n");
    Quit(SUCCESS);
  }else {
    printf ("RESULT: SACK OK\n");
    Quit(SUCCESS);
  }
}

void DSACK_GetSB (void *opt, int optlen, int ptr, uint32 *sb, int *numsb)
{

  int len = ((uint8*)opt)[ptr + 1] ;
  int i;

  if (len > 2) {

    *numsb = (len - 2)/8;

  } else {

    printf("RETURN CODE: %d\n", BAD_OPT_LEN);
    Quit (BAD_OPT_LEN);

  }

  for (i = 0 ; i < 2 * (*numsb); i++) {
    memcpy(&sb[i], ((char *)opt) + ptr + 2 + i * sizeof(uint32), sizeof(uint32));	
    sb[i] = ntohl(sb[i]);
  }

}
