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
#include "test_one_byte_req.h"

extern struct TcpSession session;
extern struct History history[];

void OneByteReqTest(uint32 sourceIpAddress, 
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
    printf("ERROR: Could not allocate opt\nRETURN CODE: %d\n", ERR_MEM_ALLOC);
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
		       0,   
		       NULL,
		       mss, 
		       optlen, 
		       opt,
		       8000/mss,
		       100000,
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\nRETURN CODE: %d", 
	   NO_SESSION_ESTABLISH);
    Quit(NO_SESSION_ESTABLISH);
  }


  SendRequestInPieces(session.filename, (void *)OneByteReqAckData);
  rcvData(OneByteReqAckData);

}

void SendRequestInPieces(char *filename, void (*ackData)(struct IPPacket *p)) 
{

  struct IPPacket *p, *datapkt;
  struct PacketInfo pi;
  char *read_packet;
  int i ;
  uint16 lastSeqSent = session.snd_nxt; 
  double startTime;
  char *dataptr ; 
  char data[MAXREQUESTLEN];
  int datalen;

  if (session.debug) {
    printf("In SendRequestInPieces...\n");
  }
  
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

  for (i = 0 ; i < datalen ; i++) {
    
    datapkt = AllocateIPPacket(0, 0, 1, "SackRcvr (DataPkt)");

    dataptr = (char *)datapkt->tcp + sizeof(struct TcpHeader);
    memcpy((void *)dataptr, (void *)data + i, 1);

    SendSessionPacket(datapkt, 
		      sizeof(struct IpHeader) + sizeof(struct TcpHeader) + 1, 
		      TCPFLAGS_PSH | TCPFLAGS_ACK, 
		      0, 
		      0, 
		      0);

    startTime = GetTime();

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

	  StorePacket(p);
	  session.snd_nxt++;
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

	  /* if the packet also contains data, receive it and send an ack if needed */
	  (*ackData)(p);

	  free(p);
	  break;

	}
	/* 
	 * otherwise, this is a bad packet
	 * we must quit
	 */
	//processBadPacket(p);
      }

      if (GetTime() - startTime >= REXMITDELAY) {
	printf ("ERROR: no response\nRETURN CODE: %d", NO_CONNECTION);
	Quit(NO_CONNECTION);
      }
    }

    free(datapkt);

  }

  if (session.debug) {
    printf("Out SendRequestInPieces...\n");
  }

}


void OneByteReqAckData (struct IPPacket *p) 
{

  uint32 seq = history[session.hsz - 1].seqno;
  uint16 datalen = history[session.hsz - 1].dlen;
  int fin = history[session.hsz - 1].fin; 
  int i;
  struct IPPacket *ackpkt;
  static int seen_datalen = 0;

  if (session.debug) {
    printf("In OneByteReqAckData...\n");
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

    session.totDataPktsRcvd++;

    if (session.verbose) {
      printf ("r %f %d %d\n", GetTime() - session.epochTime, seq-session.irs, seq-session.irs+datalen);
    }
  
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
    end = start + datalen ; 
    if (session.debug) {
      printf ("rcved = %d-%d\n", start, end);
    }
    for (i = start ; i < end ; i++) {
      session.dataRcvd[i] = 1 ; 
    }

    start = session.rcv_nxt - session.irs ; 
    end = session.mss * session.maxpkts; 
    for (i = start ; i < end ; i++) {
      if (session.dataRcvd[i] == 0) {
	break ;
      }
      session.rcv_nxt++;
    }
  }


  if (datalen > 0) {

    if (session.verbose) {
      printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt-session.irs);
    }


    /* Allocate space for ACK packet */
    ackpkt = AllocateIPPacket(0,0,0,"TotData (ACK)");


    SendSessionPacket(ackpkt, 
		      sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		      TCPFLAGS_ACK, 
		      0,
		      0, 
		      0);

  }

  if (fin) {

    if (session.totDataPktsRcvd == 0) {

      printf("Not enough packets\nRETURN CODE: %d\n", NO_DATA_RCVD);

    }else {

      printf("mss = %d pkts: %d Totdata = %d\n", 
	     seen_datalen, 
	     session.totDataPktsRcvd,
	     session.rcv_nxt - session.irs);
      printf("session.rtt = %f\n", session.rtt);
      Quit(SUCCESS); 
    }

  }

  if (session.debug) {
    printf("Out of OneByteReqAckData...\n");
  }

}
