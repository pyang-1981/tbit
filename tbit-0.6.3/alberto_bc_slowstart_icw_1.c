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
#include "capture.h"
#include "tbit.h"
#include "history.h"
#include "bc_slowstart_icw_1.h"

extern struct TcpSession session;
extern struct History history[];

void BCSlowStartICW1Test(uint32 sourceIpAddress, uint16 sourcePort, \
			 uint32 targetIpAddress, uint16 targetPort, \
			 int mss)
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
		       0,     /* ip_optlen */
		       NULL,  /* ip_opt pointer */
		       mss, 
		       optlen, 
		       opt,
		       8000/mss,
		       1000,
		       0,
		       0) == 0) {
    printf("ERROR: Couldn't establish session\n");
    Quit(NO_SESSION_ESTABLISH);

  }
  
  SendRequest(session.filename, (void *)BCSlowStartICW1AckData); 
  rcvData(BCSlowStartICW1AckData);

  free(opt);
}

void BCSlowStartICW1AckData(struct IPPacket *p) 
{

  uint32 seq = history[session.hsz - 1].seqno;
  uint16 datalen = history[session.hsz-1].dlen;
  int fin = history[session.hsz - 1].fin; 
  int i;
  struct IPPacket *ackpkt;
  static int seen_datalen = 0;
  static int last_window = 0;
  static int abc_window_started = 0;
  static int abc_window = 0;
  int pkt_number = 0;
  static int last_seen_datalen = 0;
  static float pkt_7th_arr_time = 0;
  static int cum_pkts = 0;
  float this_pkt_arr_time = 0; 
  static float last_pkt_arr_time = 0; 
  static float last_snt_ack_time = 0; 
  static float this_ack_snt_time = 0; 
  float diff;
  static int transition = 0;
  static int curr_window = 0;
  static int new_last_window = 0;
  static int win2 = 0;
  static int win3 = 0;
  static int win4 = 0;
  static int win5 = 0;
  static int num_win = 1;
  static int counting_N = 0;
  static int N = 0;
  static int num_acks_within_rtt = 0;

  if (session.debug) {
    printf("In BCSlowStartAckData...\n");
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
    
    if (seq - session.irs == 1) {

      char *http_code = (char *)calloc(4, sizeof(char));
      /* Response to request packet --> check HTTP response code */
      memcpy(http_code, ((char *)(p->tcp) + sizeof(struct TcpHeader) + history[session.hsz - 1].optlen + 9), 3);
      if (strncmp(http_code, HTTP_OK, 3) != 0) {
	printf("HTTP ERROR - HTTP RESPONSE CODE: %s\nRETURN CODE: %d\n", http_code, atoi(http_code));
	Quit(atoi(http_code));
      }

      printf("seq: %d HTTP RESPONSE CODE: %s\n", seq - session.irs, http_code);

      free(http_code);
      
    }
    
    if (session.verbose) {
      printf ("r %f %d %d\n", 
	      GetTime() - session.epochTime,
	      seq - session.irs, 
	      seq - session.irs + datalen);
    }

    pkt_number = (int)ceil((float)(seq + datalen - 1 - session.irs) / (float)seen_datalen);

    if (last_seen_datalen != datalen) {
      if (last_seen_datalen != 0 && fin != 1) {
	printf("ERROR: Variation in packet size (%d, %d)! Ignore result...\nRETURN CODE: %d", 
	       last_seen_datalen, datalen, PKT_SIZE_CHANGED);
	Quit(PKT_SIZE_CHANGED);
      }else {
	last_seen_datalen = datalen;
      }
    }

    session.totDataPktsRcvd++;
    if (counting_N == 1) {
      N += 1;
    }

    if (session.maxseqseen < seq + datalen - 1) { /* in-sequence packet */

      session.maxseqseen = seq + datalen - 1; 

    }else { /* Out-of-sequence packet */

      int r = reordered(p);
      int win_diff;
      int L;

      L = N - 1 - (3 + (2 * (num_acks_within_rtt - 1)));

      printf("LE: %d ACKS_RTT: %d N: %d L: %d\n", curr_window, num_acks_within_rtt, N - 1, L);
      //printf("NA: %d N: %d L: %d CURR WIN: %d WIN3: %d cum: %d\n", num_acks_within_rtt, N - 1, L, curr_window, win3, cum_pkts);

      
      if (r == 1) {
	printf("Unexpected packet reordering...\nRETURN CODE: %d", UNWANTED_PKT_REORDER);
	Quit(UNWANTED_PKT_REORDER);
      }    

      if (r == 2) {
	
	printf("Retransmission detected...\n");
	
	//last_window = (int)ceil((float)(session.maxseqseen - session.irs)/(float)seen_datalen) - 7;
	//win_diff = abc_window - last_window;
	win_diff = abc_window - win3;

	printf("RESULT: session.rtt = %f ", session.rtt);
	printf("LastWindow: %d ABC Window: %d ", last_window, abc_window);
	
	if (win_diff ==  1) {
	  
	  printf("LIMIT: %d PACKET_COUNTING\n", win_diff);
	  Quit(SUCCESS);

	} else {

	  if (win_diff > 1) {
	    
	    printf("LIMIT: %d APPROPRIATE_BYTE_COUNTING\n",  win_diff);
	    Quit(SUCCESS);

	  }else {
	    
	    printf("LIMIT: %d UNKNOWN_CASE\nRETURN CODE: %d", win_diff, UNKNOWN_BEHAVIOR);	    
	    Quit(UNKNOWN_BEHAVIOR);
	    
	  }
	    
	}	  
	  
	Quit(SUCCESS);
	  
      }
    }
  }
  
  /* from TCP/IP vol. 2, p 808 */
  /* Test: 
     1. The next byte to be rcvd should be less or equal than seq
     (seq = first byte in the rcvd data segment) AND
     2. The first byte in the rcvd data segment must be within the
     usable window AND
     3. The next byte to be received must be less than or equal than
     the last byte in the received segment AND
     4. The last byte in the rcvd data segment must be inside the usable window
  */
  
  if (/* 1 */ (session.rcv_nxt <= seq) && 
      /* 2 */ (seq < (session.rcv_nxt + session.rcv_wnd))  &&
      /* 3 */ (session.rcv_nxt <= (seq + datalen)) && 
      /* 4 */ ((seq + datalen - 1) < (session.rcv_nxt + session.rcv_wnd))) {
    
    int start, end; 

    start = seq - session.irs ; 
    end = start + datalen; 

    if (session.debug) {
      printf ("rcvd = %d-%d\n", start, end);
    }

    for (i = start ; i < end ; i++) {
      session.dataRcvd[i] = 1 ; 
    }

    start = session.rcv_nxt - session.irs; 
    end = session.mss * session.maxpkts; 

    for (i = start ; i < end ; i ++) {
      if (session.dataRcvd[i] == 0) {
	break;
      }
      session.rcv_nxt++;
    }
  }


  /* Compute Window Sizes */

  if (pkt_number == 1) {
    last_pkt_arr_time = GetTime() - session.epochTime;
  }

  if (datalen > 0) {


    this_pkt_arr_time = GetTime() - session.epochTime;
    diff = this_pkt_arr_time - last_pkt_arr_time;

    if (diff > 0.5 * session.rtt) {

      transition = 1;
      switch(num_win) {
      case 1:
      case 2:
	win2 = curr_window;
	break;
      case 3:
	win3 = curr_window;
	break;
      case 4:
	win4 = curr_window;
	break;
      case 5:
	win5 = curr_window;
	break;
      }

      num_win += 1;
      last_pkt_arr_time = this_pkt_arr_time;
      printf("Transition - d: %f win(%d): %d...\n", diff, num_win, curr_window);

    }
    
    if (transition == 0) {

      curr_window += 1;

    }else {
      new_last_window = curr_window;
      curr_window = 1;
      transition = 0;
    }
  }

  /* *****************************/

  if (pkt_number == 7) {
    
    if (pkt_7th_arr_time == 0) {
      //pkt_7th_arr_time = GetTime() - session.epochTime;
      pkt_7th_arr_time = this_pkt_arr_time;
    }

    printf ("PN: %d AT: %f RTT: %f\n", 
	    pkt_number, 
	    pkt_7th_arr_time, 
	    session.rtt);
  }

  if (pkt_number > 7 && abc_window_started == 0) {
  
    //this_pkt_arr_time = GetTime() - session.epochTime;
    diff = this_pkt_arr_time - pkt_7th_arr_time;

    printf ("PN: %d AT: %f D: %f RTT: %f\n", 
	    pkt_number, 
	    this_pkt_arr_time, 
	    diff, 
	    session.rtt);

    if (diff > session.rtt) {
      printf("Starting ABC...\n");
      abc_window_started = 1;
      abc_window += cum_pkts;
    }   

    if (abc_window_started == 0) {
      cum_pkts += 1;
    }

  }
  
  if (pkt_number >= 4 && abc_window_started == 0) {
    last_window += 1;
  }

  if (abc_window_started) {
    abc_window += 1;
  }

  if ((pkt_number <= 3) || pkt_number == 7) {

    if (pkt_number == 7) {      
      counting_N  = 1;
    }

    this_ack_snt_time =  GetTime() - session.epochTime;
    if (last_snt_ack_time - this_ack_snt_time < 0.75 * session.rtt) {
      num_acks_within_rtt += 1;
    }else {
      num_acks_within_rtt = 1;
      last_snt_ack_time = this_ack_snt_time;
    }

    /* Allocate IP ACK packet */
    ackpkt = AllocateIPPacket(0, 0, 0, "BCSlowStart (ACK)");

    if (session.verbose && datalen > 0) {
      printf ("a %f %d\n", GetTime() - session.epochTime, session.rcv_nxt - session.irs);
    }

    SendSessionPacket(ackpkt, 
		      sizeof(struct IpHeader) + sizeof(struct TcpHeader),
		      TCPFLAGS_ACK, 
		      0 /* ip_opt_len */, 
		      0 /* tcp_opt len */, 
		      0 /* tos */);
   
    free(ackpkt);

  }

  if (fin) {
    printf("Not enough pakets\nRETURN CODE: %d\n", NOT_ENOUGH_PKTS);
    Quit(NOT_ENOUGH_PKTS);
  }

  if (session.debug) {
    printf("Out of BCSlowStartICW1AckData...\n");
  }
  
}
