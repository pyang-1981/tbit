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
#include "piggyfin.h"

extern struct TcpSession session;
extern struct History history[];

void PiggyFINTest (uint32 sourceIpAddress, uint16 sourcePort, uint32 targetIpAddress, uint16 targetPort, int mss) 
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
			     NULL, /* ip_opt pointer */
			     mss,
			     optlen,
			     opt,
			     10000/mss,
			     1000,
			     0, 
			     0) == 0) {
		printf("ERROR: Couldn't establish session\n");
		Quit(NO_SESSION_ESTABLISH);
	}

	SendRequest(session.filename, (void *)PiggyFINAckData); 
	rcvData (PiggyFINAckData);

}

void PiggyFINAckData (struct IPPacket *p) 
{

  uint32 seq = history[session.hsz-1].seqno;
  uint16 datalen = history[session.hsz-1].dlen;
  int fin = history[session.hsz-1].fin; 
  int i;
  struct IPPacket ackpkt ;
  
  if (session.debug) {
    printf ("datalen = %d\n\n", (int)datalen);
  }

  if ((seq + datalen - session.irs) > session.mss * session.maxpkts) {

    printf ("ERROR: buffer overflow: %u %d %u %d %d\n", 
	    seq, datalen, session.irs, seq+datalen-session.irs, session.mss*session.maxpkts);
    Quit(BUFFER_OVERFLOW); 
  }

  if (fin) {
    int piggyback = 0;
    if (datalen > 0) piggyback = 1; 
    printf ("#### piggyback = %d\n", piggyback);
    Quit(SUCCESS);
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
  if(session.maxseqseen < seq+datalen-1) {
    session.maxseqseen = seq +datalen-1; 
  }
  /* from TCP/IP vol. 2, p 808 */
  if ((session.rcv_nxt <= seq) && (seq < (session.rcv_nxt+session.rcv_wnd))  &&
      (session.rcv_nxt <= (seq+datalen)) && ((seq+datalen-1) < (session.rcv_nxt + session.rcv_wnd))) {
    int start = seq - session.irs ; 
    int end = start + datalen ; 
    for (i = start ; i < end ; i++) {
      session.dataRcvd[i] = 1 ; 
    }
    start = session.rcv_nxt - session.irs ; 
    end = session.mss*session.maxpkts ; 
    for (i = start ; i < end ; i ++) {
      if (session.dataRcvd[i] == 0) {
	break ;
      }
      session.rcv_nxt ++ ;
    }
  }

  SendSessionPacket (&ackpkt, 
		     //sizeof(struct IPPacket), 
		     sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		     TCPFLAGS_ACK, 
		     0, /* ip options length */
		     0, /* tcp options length */
		     0);

}
