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
#include "ipoptions_rr_syn.h"

extern struct TcpSession session;
extern struct History history[];

void IPRROptionTest(uint32 sourceIpAddress, \
		   uint16 sourcePort, \
		   uint32 targetIpAddress, \
		   uint16 targetPort, \
		   int mss)

{

  /* Define IP options structure */
  int ip_optlen; 
  char *ip_opt;

  /* Define TCP options structure */
  int optlen; 
  char *opt;

  /* hardwire IP option for now  */
  int ip_opt_code = IPOPT_RR;

  /*** IP Options  ***/
  switch (ip_opt_code) {

  case IPOPT_NOP:

    ip_optlen = 4;
    if ((ip_opt = (char *)calloc(sizeof(uint8), ip_optlen)) == NULL)	{
      perror("ERROR: Could not allocate (IP) opt:");
      Quit(ERR_MEM_ALLOC);
    }

    ip_opt[0] = (uint8)IPOPT_NOP;
    ip_opt[1] = (uint8)IPOPT_NOP;
    ip_opt[2] = (uint8)IPOPT_NOP;
    ip_opt[3] = (uint8)IPOPT_EOL;
    break;
    
  case IPOPT_RR:

    ip_optlen = (uint8)IPOLEN_RR + 1;
    printf("ip_optlen: %d\n", ip_optlen);
    if ((ip_opt = (char *)calloc(sizeof(uint8), ip_optlen)) == NULL)	{
      perror("ERROR: Could not allocate (IP) opt:");
      Quit(ERR_MEM_ALLOC);
    }

    /* Fill Record Route option fields */
    ip_opt[0] = (uint8)IPOPT_RR;
    ip_opt[1] = (uint8)IPOLEN_RR;
    ip_opt[2] = (uint8)4;

    /* Pad IP options to ensure 32-bit alignment */
    ip_opt[39] = (uint8)IPOPT_EOL;
    
    break;

  default:
    printf("IP Options code not supported....\n");
    Quit(FAIL);

  }

  /*** TCP Options  ***/
  optlen = 4 ;
  if ((opt = (char *)calloc(sizeof(uint8), optlen)) == NULL)	{
    perror("ERROR: Could not allocate (TCP) opt:");
    Quit(ERR_MEM_ALLOC);
  }

  /* MSS option */
  opt[0] = (uint8)TCPOPT_MAXSEG; 
  opt[1] = (uint8)TCPOLEN_MAXSEG; 
  *((uint16 *)((char *)opt + 2)) = htons(mss);

  if (EstablishSession(sourceIpAddress,\
		       sourcePort,\
		       targetIpAddress,\
		       targetPort,\
		       ip_optlen, /* ip_opt len */
		       ip_opt,    /* ip_opt pointer */
		       mss,\
		       optlen,\
		       opt,\
		       5,\
		       5,\
		       0,\
		       0) == 0) {

    printf("ERROR: Couldn't establish session\n");
    Quit(NO_SESSION_ESTABLISH);

  }

  check_rr_ipoption(ip_opt_code);
  Quit(SUCCESS);	

}

void check_rr_ipoption(int ip_opt_code) 
{
  int isipoptions = 0;
  int ip_opt_len = 0;
  int i,j ; 
	
  for (i = 1; i < session.hsz; i++) {

    if ((history[i].type == RCVD) && (history[i].ack) && (history[i].syn)) {

      j = 0;

      printf("RCVD IPOPTLEN: %d\n", history[i].ip_optlen);
      while (j < history[i].ip_optlen) {

	switch ((unsigned char)history[i].ip_opt[j]) {
	case IPOPT_EOL:
	  j = j + IPOLEN_EOL;
	  break; 

	case IPOPT_NOP:
	  j = j + IPOLEN_NOP ;
	  break;

	case IPOPT_RR:
	  isipoptions = 1;
	  ip_opt_len = (uint8)history[i].ip_opt[j + 1];
	  j = history[i].ip_optlen + 1;
	  break ; 

	default: 
	  if ((uint8)history[i].ip_opt[j + 1] > 0) {
	    j = j + (uint8)history[i].ip_opt[j + 1] ;
	  }else {
	    Quit(20); 
	  }
	  break ;
	}
      } 
    }
  }

  printf ("#### IP Record Route Option = %d OptLen = %d\n", isipoptions, ip_opt_len);

}
