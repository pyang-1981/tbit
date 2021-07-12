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
#include "initwin.h"

extern struct TcpSession session;
extern struct History history[];

int finflag = 0 ; 

void InitWinTest (uint32 sourceIpAddress, uint16 sourcePort, uint32 targetIpAddress, uint16 targetPort, int mss) 
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
		       0,     /* ip_opt len */
		       NULL,  /* ip_opt pointer */
		       mss,  
		       optlen,
		       opt,
		       100,
		       100,
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\nRETURN CODE: %d\n", 
	   NO_SESSION_ESTABLISH);
    Quit(NO_SESSION_ESTABLISH);

  }

  SendRequest(session.filename, (void *)InitWinackData); 
  rcvData (InitWinackData);

}

void InitWinackData(struct IPPacket *p) 
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
  static int seen_datalen = 0;

  ReadIPPacket(p, &src, &dst, 
	       &sport, &dport, 
	       &seq, &ack, &flags, &win,
	       &urp, &datalen, 
	       &ip_optlen, &optlen);

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

    if (datalen > session.mss) {
      printf ("ERROR: mss=%d datalen=%d\nRETURN CODE: %d\n", 
	      session.mss, 
	      datalen, 
	      MSS_ERR);
      Quit(MSS_ERR);
    }

    if (seen_datalen < datalen) {
      seen_datalen = datalen;
    }

    if (session.verbose) {
      printf ("r %f %d %d\n", 
	      GetTime() - session.epochTime, 
	      seq - session.irs, 
	      seq - session.irs + datalen);
    }

    session.totDataPktsRcvd++;

    if (seq + datalen - 1> session.maxseqseen) {
      /* "regular" packet */
      session.maxseqseen = seq + datalen - 1; 

    }else {

      /* upon receiving first retransmission, check window size */
      InitWin((float)seen_datalen);
      Quit(SUCCESS); 

    }
  }

  if (flags & TCPFLAGS_FIN) {
    finflag = 1;
    InitWin((float)seen_datalen);
    Quit(SUCCESS);
  }

  if (session.totDataPktsRcvd >= session.maxpkts) {
    printf("Not enough pakets\nRETURN CODE: %d\n", NOT_ENOUGH_PKTS);
    Quit(NOT_ENOUGH_PKTS);
  }

}

void InitWin(float s) {

  int initWin = (int)ceil((session.maxseqseen - session.irs) / (float)(s));

  if (finflag == 0) {
    printf ("#### initWin = %d packets, bytes = %d MaxData = %.0f\n", 
	    initWin, session.maxseqseen - session.irs, s);
  }
  else {
    printf ("#### initWin > %d packets, bytes = %d MaxData = %.0f\n", 
	    initWin, session.maxseqseen - session.irs, s);
  }
}
