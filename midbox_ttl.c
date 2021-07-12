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
#include "midbox_ttl.h"

extern struct TcpSession session;
extern struct History history[];

void MidBoxTTLTest(uint32 sourceAddress, uint16 sourcePort, uint32 targetAddress, uint16 targetPort, int mss) 
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
  int optlen; 
  char *opt; 

  session.src        = sourceAddress;
  session.sport      = sourcePort;
  session.dst        = targetAddress;
  session.dport      = targetPort;
  session.rcv_wnd    = 8000/mss;
  session.snd_nxt    = (uint32)mrand48(); /* random initial sequence number */
  session.iss        = session.snd_nxt;
  session.rcv_nxt    = 0;
  session.irs        = 0;
  session.mss        = mss ;
  session.maxseqseen = 0 ; 
  session.epochTime  = GetTime ();
  session.maxpkts    = 10000; 

  session.curr_ttl = 1;

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
	
  /* allocate the syn packet -- Changed for new IPPacket structure */
  synPacket = AllocateIPPacket(0, optlen, 0, "MidBoxTTL (SYN)");

  /* Copy TCP options at the end of TcpHeader structure - New */
  if (optlen > 0) {
    memcpy((char *)synPacket->tcp + sizeof(struct TcpHeader), opt, optlen);
  }

  if (session.verbose) {
    printf ("s %f ttl: %d\n", GetTime() - session.epochTime, session.curr_ttl);
  }

  SendSessionPacket(synPacket, 
		    sizeof(struct IpHeader) + sizeof(struct TcpHeader) + optlen,
		    TCPFLAGS_SYN, 
		    0,
		    optlen, 
		    iptos);	 

  timeoutTime = GetTime() + 1;

  /* 
   * Wait for SYN/ACK and retransmit SYN if appropriate 
   * not great, but it gets the job done 
   */

  while(!synAckReceived && numRetransmits <= 30) {

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
	  }
	  else {
	    //processBadPacket(p);
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
	    session.totRcvd++;
	    break ;

	  }else {

	    if ((p->tcp->tcp_flags) & (TCPFLAGS_RST)) {
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

      session.curr_ttl += 1;
      if (session.verbose) {
	printf ("s %f ttl: %d\n", GetTime() - session.epochTime, session.curr_ttl);
      }

      SendSessionPacket(synPacket, 
			sizeof(struct IpHeader) + sizeof(struct TcpHeader) + optlen,
			TCPFLAGS_SYN,
			0,
			optlen, 
			iptos);	 

      timeoutTime = GetTime() + 1;
      numRetransmits++;

    }

  }
	
  if (numRetransmits >= 60) {
    printf("ERROR: No SYN/ACK Received...\nRETURN CODE: %d\n", NO_SYNACK_RCVD);
    Quit(NO_SYNACK_RCVD);
  }

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

  /* Reduce TTL to one less than SYN TTL  */
  session.curr_ttl -= 1;

  SendRequest(session.filename, (void *)MidBoxTTLAckData); 
  printf("After Request\n");
  rcvData(MidBoxTTLAckData);

}
	
void MidBoxTTLAckData (struct IPPacket *p) 
{

  uint32 seq = history[session.hsz - 1].seqno;
  uint16 datalen = history[session.hsz - 1].dlen;
  int fin = history[session.hsz - 1].fin; 
  int i;
  struct IPPacket *ackpkt;
  static int seen_datalen = 0;

  if (session.debug) {
    printf("In MidBoxAckData...\n");
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

    session.totDataPktsRcvd ++ ;
    if (session.verbose) {
      printf ("r %f %d %d\n", GetTime() - session.epochTime, seq-session.irs, seq-session.irs+datalen);
    }
  }

  if (seen_datalen < datalen) {
    seen_datalen = datalen;
  }

  if (datalen > session.mss) {
    printf ("ERROR: mss=%d datalen=%d\nRETURN CODE: %d\n", 
	    session.mss, 
	    datalen,
	    MSS_ERR);
    Quit(MSS_ERR);
  }

 
  if(session.maxseqseen < seq + datalen - 1) {
    session.maxseqseen = seq + datalen - 1; 
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
    end = start + datalen; 

    if (session.debug) {
      printf ("rcved = %d-%d\n", start, end);
    }
    for (i = start ; i < end ; i++) {
      session.dataRcvd[i] = 1 ; 
    }

    start = session.rcv_nxt - session.irs; 
    end = session.mss * session.maxpkts; 
    for (i = start ; i < end ; i ++) {
      if (session.dataRcvd[i] == 0) {
	break ;
      }
      session.rcv_nxt++ ;
    }
  }

  if (datalen > 0) {

    if (session.verbose) {
      printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt-session.irs);
    }


    /* Allocate space for ACK packet */
    ackpkt = AllocateIPPacket(0,0,0,"TotData (ACK)");


    SendSessionPacket (ackpkt, 
		       sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		       TCPFLAGS_ACK, 
		       0,
		       0, 
		       0);

  }
  if (fin) {
    printf("mss = %d Totdata = %d SYN TTL: %d DATA PKT TTL: %d \n", 
	   seen_datalen, 
	   session.rcv_nxt - session.irs,
	   session.curr_ttl + 1,
	   session.curr_ttl);

    printf("session.rtt = %f\n", session.rtt);
    Quit(SUCCESS); 
  }


  if (session.debug) {
    printf("Out of MidBoxAckData...\n");
  }

}
