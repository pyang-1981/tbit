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
#include "timestamp.h"

extern struct TcpSession session;
extern struct History history[];

void TimeStampTest (uint32 sourceIpAddress, uint16 sourcePort, uint32 targetIpAddress, uint16 targetPort, int mss) 
{
  int optlen ; 
  char *opt	; 

  optlen = 16 ;
  if ((opt=(char *)calloc(sizeof(uint8), optlen)) == NULL)	{
    perror("ERROR: Could not allocate opt:");
    Quit(ERR_MEM_ALLOC);
  }

  /* mss option */
  opt[0] = (uint8)TCPOPT_MAXSEG ; 
  opt[1] = (uint8)TCPOLEN_MAXSEG ; 
  *((uint16 *)((char *)opt + 2)) = htons(mss);

  /* align 4-byte boundries */
  opt[4] = (uint8)TCPOPT_NOP ;
  opt[5] = (uint8)TCPOPT_NOP ;

  /* Timestamp option */
  opt[6] = (uint8)TCPOPT_TIMESTAMP;
  opt[7] = (uint8)TCPOLEN_TIMESTAMP;
  *((uint32 *)((char *)opt + 8)) = htonl(1);
  *((uint32 *)((char *)opt + 12)) = htonl(0);

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
		       5,
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\n");
    Quit(NO_SESSION_ESTABLISH);
  }

  check_timestamp();
  Quit(SUCCESS);	

}

void check_timestamp () 
{
  int istimestamp = 0;
  int i,j ; 
	
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

	case TCPOPT_TIMESTAMP:
	  istimestamp = 1;
	  j = history[i].optlen+1;
	  break ; 

	default: 
	  if ((uint8)history[i].opt[j+1] > 0) {
	    j = j + (uint8)history[i].opt[j+1] ;
	  } 
	  else {
	    Quit(20); 
	  }
	  break ;
	}
      } 
    }
  }
  printf ("#### timestamp=%d\n", istimestamp);
}
