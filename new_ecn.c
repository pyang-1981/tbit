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
#include "new_ecn.h"

extern struct TcpSession session;
extern struct History history[];

int SYNACK_ECN;

void NewECNTest (uint32 sourceIpAddress, uint16 sourcePort, uint32 targetIpAddress, uint16 targetPort, int mss) 
{
  int optlen; 
  char *opt; 
  uint8 tcp_flags;

  optlen = 4 ;
  if ((opt=(char *)calloc(sizeof(uint8), optlen)) == NULL)	{
    perror("ERROR: Could not allocate opt:");
    Quit(ERR_MEM_ALLOC);
  }

  /* mss option */
  opt[0] = (uint8)TCPOPT_MAXSEG ; 
  opt[1] = (uint8)TCPOLEN_MAXSEG ; 
  *((uint16 *)((char *)opt+2)) = htons(mss);
	
  /* Set tcp flags for establishing ECN-capable connection */
  tcp_flags = TCPFLAGS_ECN_ECHO | TCPFLAGS_CWR;

  /* Establish connection with server */
  if (EstablishSession(sourceIpAddress,
		       sourcePort,
		       targetIpAddress,
		       targetPort,
		       0,    /* ip_opt len */
		       NULL, /* ip_opt pointer */
		       mss, 
		       optlen, 
		       opt,
		       128,   /* make max window big   */
		       10000, /* allow lots of packets */
		       0,
		       tcp_flags) == 0) {

    printf("ERROR: Couldn't establish session\nRETURN CODE: %d\n", NO_SESSION_ESTABLISH);
    Quit(NO_SESSION_ESTABLISH);
  }

  CheckSYNACK();

  if (SYNACK_ECN == 0) {
    printf ("Totdata = 0 SYNACK_ECN: 0 ECN_ECHO: 0 ECT00: 0 ECT01: 0 ECT10: 0 ECT11: 0\n");
    Quit(SUCCESS);
  }

  SendRequest(session.filename, (void *)NewECNAckData); 
  rcvData (NewECNAckData);

}

void NewECNAckData (struct IPPacket *p) 
{

  uint32 seq = history[session.hsz - 1].seqno;
  uint16 datalen = history[session.hsz - 1].dlen;
  int fin = history[session.hsz - 1].fin; 
  int i;
  struct IPPacket *ackpkt;
  static int ECT_00 = 0;
  static int ECT_01 = 0;
  static int ECT_10 = 0;
  static int ECT_11 = 0;
  static int ECN_ECHO = 0;
  uint8 tcp_flags;


  /* Legend:
   * ECN_ECHO: counts packets with TCP header ECN bit set
   * ECT_XX: counts packets with ECT codepoint XX (IP)
   */
  
  if (datalen > session.mss) {
    printf ("ERROR: mss=%d datalen=%d\nRETURN CODE: %d\n", session.mss, datalen, MSS_ERR);
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
      printf ("r %f %d %d\n", 
	      GetTime() - session.epochTime, 
	      seq - session.irs, 
	      seq - session.irs + datalen);
    }

  }

  /* Check if packet has the ECN_ECHO flag set */
  if (history[session.hsz - 1].ecn_echo) {
    ECN_ECHO += 1;
  }

  if ((p->ip->ip_tos & 0x17) == 0) {
    ECT_00 += 1;
  }
  if ((p->ip->ip_tos & 0x17) == 1) {
    ECT_01 += 1;
  }
  if ((p->ip->ip_tos & 0x17) == 2) {
    ECT_10 += 1;
  }
  if ((p->ip->ip_tos & 0x17) == 3) {
    ECT_11 += 1;
  }

  if(session.maxseqseen < seq + datalen - 1) {

    session.maxseqseen = seq + datalen - 1; 

  }else {
    
    if (datalen > 0) {
      if (reordered(p) != 1) {
	session.num_unwanted_drops += 1;
      }
    }
  }

  /* from TCP/IP vol. 2, p 808 */
  if ((session.rcv_nxt <= seq) && (seq < (session.rcv_nxt+session.rcv_wnd))  &&
      (session.rcv_nxt <= (seq + datalen)) && ((seq+datalen-1) < (session.rcv_nxt + session.rcv_wnd))) {

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
    end = session.mss * session.maxpkts ; 

    for (i = start ; i < end ; i++) {

      if (session.dataRcvd[i] == 0) {
	break ;
      }

      session.rcv_nxt++ ;

    }
  }

  if (datalen > 0) {
 
   if (session.verbose) {
      printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt - session.irs);
    }

    ackpkt = AllocateIPPacket(0, 0, 0, "NewECN (ACK)");
    
    if ((p->ip->ip_tos & 0x17) == 3) {
      
      tcp_flags = TCPFLAGS_ACK | TCPFLAGS_ECN_ECHO;
      
    }else {
      
      tcp_flags = TCPFLAGS_ACK;

    }

    SendSessionPacket (ackpkt, 
		       sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		       tcp_flags, 
		       0,
		       0, 
		       3); 

  }

  if (fin) {
    printf ("Totdata = %d SYNACK_ECN: %d ECN_ECHO: %d ECT00: %d ECT01: %d ECT10: %d ECT11: %d drops: %d\n", 
	    session.rcv_nxt - session.irs,
	    SYNACK_ECN,
	    ECN_ECHO,
	    ECT_00,
	    ECT_01,
	    ECT_10,
	    ECT_11,
	    session.num_unwanted_drops);

    Quit(SUCCESS); 

  }

}

void CheckSYNACK() 
{

  int i; 
  
  for (i = 0 ; i < session.hsz; i++) {

    if ((history[i].type == RCVD) && (history[i].syn == 1) && (history[i].ack == 1)) {

      if (history[i].ecn_echo == 1)  {

	SYNACK_ECN = 1; /* SYN/ACK rcvd with ECN_ECHO flag set*/

	if (history[i].cwr == 1) {
	   SYNACK_ECN = 2; /* SYN/ACK rcvd with ECN_ECHO and CWR flags set*/
	}

      }else {

	SYNACK_ECN = 0;

      }

      break;

    }
  }
}
