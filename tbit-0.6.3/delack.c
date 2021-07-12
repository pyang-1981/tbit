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
#include "delack.h"

extern struct TcpSession session;
extern struct History history[];

void DelAckTest (uint32 sourceAddress, uint16 sourcePort, uint32 targetAddress, uint16 targetPort, int mss) 
{
  if (EstablishSession(sourceAddress,
		       sourcePort,
		       targetAddress,
		       targetPort,
		       0,    /* ip_optlen */
		       NULL, /* ip_opt pointer */
		       mss, 
		       0,
		       NULL,
		       5,
		       5,
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\nRETURN CODE: %d\n", 
	   NO_SESSION_ESTABLISH);
    Quit(NO_SESSION_ESTABLISH);
  }
 
  SendSlowRequest();
  checkDelAck();
  Quit(SUCCESS);

}

void SendSlowRequest() 
{

  struct IPPacket *p, *datapkt;
  struct PacketInfo pi;
  char *read_packet;
  uint32 lastSeqSeen = session.snd_nxt - 1; 
  double startTime;
  char *dataptr ; 
  char data[MAXREQUESTLEN];
  int datalen;
  int datasz ; 

  p = NULL; 
  datapkt = NULL;

  /*
   * We will send several data packets, 
   * each carrying a give number of bytes, seperated by 
   * a fixed time interval each.
   * we will then count the number
   * of acks coming back. 
   */
  
  datalen = PrepareRequest(data, session.filename);
  datasz = datalen - 2;

  while (1) {
 
    int sent = session.snd_nxt - session.iss - 1 ; 
    if ((datalen - sent) < datasz) {
      datasz = datalen - sent ; 
    }
    if (datasz <= 0) {
      break; 
    }

    /* Allocate space for datapkt structure */
    datapkt = AllocateIPPacket(0, 0, datasz, "DelACK (DatPkt)");

    /* Copy data into packet */
    dataptr = (char *)datapkt->tcp + sizeof(struct TcpHeader);
    memcpy((void *)dataptr, (void *)data + sent, datasz);
    
    SendSessionPacket(datapkt, 
		      sizeof(struct IpHeader) + sizeof(struct TcpHeader) + datasz,
		      TCPFLAGS_PSH | TCPFLAGS_ACK, 
		      0,  /* ip opt len */
		      0,  /* tcp opt len */
		      0); /* tos */
    
    session.snd_nxt += datasz;
    startTime = GetTime();

    while (GetTime() - startTime < 0.05) {

      if ((read_packet = (char *)CaptureGetPacket(&pi)) != NULL) {

	int flag = 0;

	p = (struct IPPacket *)FindHeaderBoundaries(read_packet);

	/*
	 * packet that we sent?
	 */
	if (INSESSION(p,session.src,session.sport,session.dst,session.dport) &&
	    (p->tcp->tcp_flags == (TCPFLAGS_PSH | TCPFLAGS_ACK)) &&
	    (ntohl(p->tcp->tcp_seq) > lastSeqSeen) &&
	    (ntohl(p->tcp->tcp_ack) <= session.rcv_nxt) &&
	    (flag == 0)) {
	  if (session.debug) {
	    printf("saw the packet we sent\n");
	    PrintTcpPacket(p);
	  }
	  lastSeqSeen = ntohl(p->tcp->tcp_seq);
	  StorePacket(p);
	  session.totSeenSent ++ ;
	  flag = 1;
	} 

	/*
	 * from them? 
	 */ 

	if (INSESSION(p,session.dst,session.dport,session.src,session.sport) &&
	    (p->tcp->tcp_flags & TCPFLAGS_ACK) &&
	    (ntohl(p->tcp->tcp_seq) == session.rcv_nxt) &&
	    (ntohl(p->tcp->tcp_ack) >= session.snd_una) &&
	    (flag == 0)) {
	  if (ntohl(p->tcp->tcp_ack) > session.snd_una) {
	    session.snd_una  = ntohl(p->tcp->tcp_ack);
	  }
	  if (session.debug) {
	    PrintTcpPacket(p);
	  }
	  StorePacket(p);
	  session.rcv_nxt += history[session.hsz-1].dlen; 
	  session.totRcvd ++;
	  flag = 1;
	}
	/* 
	 * otherwise, this is a bad packet
	 * we must quit
	 */
	if (flag == 0) {
	  //processBadPacket(p);
	}
      }
    }

    free (datapkt);

  }
  
  /* Wait for two seconds, and read all the pkts that might come our way */
  startTime = GetTime();
  while (GetTime() - startTime < 2) {

    if ((read_packet =(char *)CaptureGetPacket(&pi)) != NULL) {

      int flag = 0;

      p = (struct IPPacket *)FindHeaderBoundaries(read_packet);

      /*
       * packet that we sent?
       */

      if (INSESSION(p,session.src,session.sport,session.dst,session.dport)) {

	if (session.debug) {
	  printf("saw the packet we sent\n");
	  PrintTcpPacket(p);
	}

	StorePacket(p);
	session.totSeenSent ++ ;
	flag = 1;

      } 
      /*
       * from them? 
       */ 
      if (INSESSION(p,session.dst,session.dport,session.src,session.sport)) { 
	if (ntohl(p->tcp->tcp_ack) > session.snd_una) {
	  session.snd_una  = ntohl(p->tcp->tcp_ack);
	}
	if (session.debug) {
	  PrintTcpPacket(p);
	}
	StorePacket(p);
	session.totRcvd ++;
	flag = 1;
      }
      /* 
       * otherwise, this is a bad packet
       * we must quit
       */
      if (flag == 0) {
	//processBadPacket(p);
      }
    }
  }
}

void checkDelAck() 
{

  int i; 
  uint32 ack;
  int delack = 1; 
  
  for (i = 0 ; i < session.hsz ; i++) {
    if ((history[i].type == SENT) &&
	(history[i].syn == 0) &&
	(history[i].dlen > 0)) {
      ack = history[i].nextbyte; 
      break;
    }
  }

  for (i = 0; i < session.hsz ; i++) {
    if ((history[i].type == RCVD) &&
	(history[i].ackno == ack)) {
      delack = 0;
      break;
    }
  }
  printf ("RESULT: DELACK = %d\n", delack);	
}
