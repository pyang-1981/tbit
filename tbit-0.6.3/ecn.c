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
#include "ecn.h"

extern struct TcpSession session;
extern struct History history[];

void ECNTest(uint32 sourceAddress, uint16 sourcePort, uint32 targetAddress, uint16 targetPort, int mss) 
{

  int rawSocket;
  struct IPPacket *p;
  struct IPPacket *synPacket;
  char *read_packet;
  struct PacketInfo pi;
  int synAckReceived = 0;
  int numRetransmits = 0;
  double timeoutTime;
  int flag=1;
  uint8 iptos = 0;	
  int optlen = 0 ;

  session.src = sourceAddress;
  session.sport = sourcePort;
  session.dst = targetAddress;
  session.dport = targetPort;
  session.rcv_wnd = 5*mss;
  session.snd_nxt = (uint32)mrand48();	/* random initial sequence number */
  session.iss = session.snd_nxt;
  session.rcv_nxt = 0;
  session.irs = 0;
  session.mss = mss ;
  session.maxseqseen = 0; 
  session.epochTime = GetTime ();
  session.maxpkts = 20; 

  if ((session.dataRcvd = (uint8 *)calloc(sizeof(uint8), mss * session.maxpkts)) == NULL) {
    printf("no memmory to store data:\nRETURN CODE: %d", ERR_MEM_ALLOC);
    Quit(ERR_MEM_ALLOC);
  }

  if ((rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("ERROR: couldn't open socket:"); 
    Quit(ERR_SOCKET_OPEN);
  }

  if (setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, (char *)&flag,sizeof(flag)) < 0) {
    perror("ERROR: couldn't set raw socket options:");
    Quit(ERR_SOCKOPT);
  }

  session.socket = rawSocket;

  SetFireWall();
	
  /* allocate the syn packet -- Changed for new IPPacket structure */
  synPacket = AllocateIPPacket(0, 0, 0, "ECN (SYN)");

  SendSessionPacket(synPacket, 
		    sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		    TCPFLAGS_SYN | TCPFLAGS_ECN_ECHO | TCPFLAGS_CWR, 
		    0,
		    optlen, 
		    iptos);	 

  timeoutTime = GetTime() + 1;

  /* 
   * Wait for SYN/ACK and retransmit SYN if appropriate 
   * not great, but it gets the job done 
   */

  while(!synAckReceived && numRetransmits < 3) {

    while(GetTime() < timeoutTime) {

      /* Have we captured any packets? */
      if ((read_packet = (char *)CaptureGetPacket(&pi)) != NULL) {

	p = (struct IPPacket *)FindHeaderBoundaries(read_packet);

	/* Received a packet from us to them */
	if (INSESSION(p, session.src, session.sport, session.dst, session.dport)) {

	  /* Is it a SYN? */
	  if (p->tcp->tcp_flags & TCPFLAGS_SYN) {
	    if (session.debug) {
	      PrintTcpPacket(p); 
	    }
	    StorePacket(p);
	    session.totSeenSent ++ ;
	  }else {
	    processBadPacket(p);
	  }
	  continue;
	}

	/* Received a packet from them to us */
	if (INSESSION(p, session.dst, session.dport, session.src, session.sport)) {

	  /* Is it a SYN/ACK? */
	  if ((p->tcp->tcp_flags & TCPFLAGS_SYN) && (p->tcp->tcp_flags & TCPFLAGS_ACK)) {

	    timeoutTime = GetTime(); /* force exit */
	    synAckReceived++;
	    if (session.debug) {
	      PrintTcpPacket(p);
	    }
	    StorePacket(p);

	    /* Save ttl for,admittedly poor,indications of reverse route change */
	    session.ttl = p->ip->ip_ttl;
	    session.snd_wnd = ntohl(p->tcp->tcp_win);
	    session.totRcvd ++;
	    break ;

	  }else {

	    if ((p->tcp->tcp_flags)& (TCPFLAGS_RST)) {
	      printf ("ERROR: EARLY_RST\n");
	      Quit(EARLY_RST);
	    }
	  }

	}
      } 
    }

    if (!synAckReceived) {

      if (session.debug) {
	printf("SYN timeout. Retransmitting\n");
      }

      SendSessionPacket(synPacket, 
			sizeof(struct IpHeader) + sizeof(struct TcpHeader) + optlen,
			TCPFLAGS_SYN | TCPFLAGS_ECN_ECHO | TCPFLAGS_CWR,
			0,
			optlen, 
			iptos);	 

      timeoutTime = GetTime() + 1;
      numRetransmits++;

    }

  }
	
  if (numRetransmits >= 3) {
    printf("ERROR: No connection after 3 retries...\nRETURN CODE: %d\n", NO_CONNECTION);
    Quit(NO_CONNECTION);
  }

  free(synPacket->ip);
  free(synPacket->tcp);
  free(synPacket);

  /* Update session variables */
  session.irs = ntohl(p->tcp->tcp_seq);
  session.dataRcvd[0] = 1 ;
  session.rcv_nxt = session.irs + 1;	/* SYN/ACK takes up a byte of seq space */
  session.snd_nxt = session.iss + 1;	/* SYN takes up a byte of seq space */
  session.snd_una = session.iss + 1;
  session.maxseqseen = ntohl(p->tcp->tcp_seq);
  session.initSession = 1;
  if (session.debug) {
    printf("src = %s:%d (%u)\n", InetAddress(session.src), session.sport, session.iss);
    printf("dst = %s:%d (%u)\n",InetAddress(session.dst), session.dport, session.irs);
  }
  
  free(synPacket->ip);
  free(synPacket->tcp);
  free(synPacket);

  DataPkt(session.filename);
	
  checkECN();
  Quit(SUCCESS);
}

void DataPkt (char *filename) 
{
  uint8 iptos = 3;
  struct IPPacket *p, *datapkt;
  struct PacketInfo pi;
  char *read_packet;
  int i ;
  int sendflag = 1 ;
  uint16 lastSeqSent = session.snd_nxt; 
  double startTime;
  char *dataptr ; 
  char data[MAXREQUESTLEN];
  int datalen;
  int ipsz; 

  datalen = PrepareRequest (data, filename);

  datapkt = AllocateIPPacket(0, 0, datalen + 1, "ECN (datapkt)");

  dataptr = (char *)datapkt->tcp + sizeof(struct TcpHeader);
  memcpy((void *)dataptr,(void *)data, datalen);

  ipsz = sizeof(struct IpHeader) + sizeof(struct TcpHeader) + datalen + 1; 
  
  /* send the data packet
   * we try to "achieve" reliability by
   * sending the packet upto 5 times, wating for
   * 2 seconds between packets
   * BAD busy-wait loop
   */

  i = 0 ;
  while(1) {

    if (sendflag == 1) {

      SendSessionPacket(datapkt, 
			ipsz, 
			TCPFLAGS_PSH | TCPFLAGS_ACK, 
			0, /* ip options len */
			0, /* tcp options len */
			iptos);

      startTime = GetTime();	
      sendflag = 0 ; 
      i ++ ;

    }

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
	StorePacket(p);
	session.snd_nxt += datalen + 1;
	session.totSeenSent ++ ;
	continue ;
      } 

      /*
       * from them? 
       */ 
      if (INSESSION(p,session.dst,session.dport,session.src,session.sport) &&
	  (p->tcp->tcp_flags & TCPFLAGS_ACK) &&
	  (ntohl(p->tcp->tcp_seq) == session.rcv_nxt) &&
	  (ntohl(p->tcp->tcp_ack) > session.snd_una)) {
	session.snd_una = ntohl(p->tcp->tcp_ack);
	if (p->ip->ip_ttl != session.ttl) {
	  session.ttl = p->ip->ip_ttl;
	}
	if (session.debug) {
	  PrintTcpPacket(p);
	}
	StorePacket(p);
	session.totRcvd ++;
	break ;
      }
      /* 
       * otherwise, this is a bad packet
       * we must quit
       */
      //processBadPacket(p);
    }
    if ((GetTime() - startTime >= 1) && (sendflag == 0) && (i < 3)) {
      sendflag = 1 ;
    }
    if (i >= 3) {
      printf ("ERROR: sent request 3 times without response\n");
      return;
    }
  }	

  free(datapkt->ip);
  free(datapkt->tcp);
  free(datapkt);

}

void checkECN () 
{
  int i; 
  int sr = 0; /* sr=1: SYN/ACK rcvd */
  int se = 0; /* se=0: no CWR/no ECHO; se=1: no CWR/ECHO; se=2: CWR/ECHO */
  int ar = 0; /* ar=0: no ACK rcvd; ar=1: ACK rcvd */
  int ae = 0; /* ae=0: ACK/no ECHO; ae=1: ACK/ECHO */
  
  for (i = 0 ; i < session.hsz; i++) {
    if ((history[i].type == RCVD) && (history[i].syn == 1) && (history[i].ack == 1)) {
      sr = 1;
      if (history[i].ecn_echo == 1)  {
	se = 1;
	if (history[i].cwr == 1) {
	  se = 2;
	}
      }
    } 
  }

  for (i = 0 ; i < session.hsz; i++) {
    if ((history[i].type == RCVD) && (history[i].syn == 0) && (history[i].ack == 1)) {
      ar = 1;
      if (history[i].ecn_echo == 1) {
	ae = 1;
      }
    }
  }
  printf ("sr=%d se=%d ar=%d ae=%d\n", sr, se, ar, ae);
}
