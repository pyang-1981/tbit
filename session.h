
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

#include <net/if.h>
#include <stdint.h>
#define MAXREQUESTLEN 1000

struct TcpSession {

  /* target name, as specified by the user */
  char targetName[MAXHOSTNAMELEN];
  
  /* DNS name of hosts */
  char targetHostName[MAXHOSTNAMELEN];	
  char sourceHostName[MAXHOSTNAMELEN];

  /* raw socket we use to send on */
  int socket;		
  
  /* connection endpoint identifiers */
  uint32 src;
  uint16 sport;
  uint32 dst;
  uint16 dport;

  /* sender info, from RFC 793 */
  uint32 iss;     // initial send sequence
  uint32 snd_una; // sequence numbers of unacknowledged data
  uint32 snd_nxt; // sequence number to be sent next
  uint16 snd_wnd; 
  uint16 sndmss;

  /* Receiver info */
  uint32 irs;
  uint32 rcv_wnd;
  uint32 rcv_nxt;
  uint32 maxseqseen;
  uint16 mss;

  /* timing */
  double rtt;
  uint8 ttl;
  double start_time;

  /* data buffer */
  unsigned char *dataRcvd ;
	
  /* basic results */
  int totSent; 
  int totRcvd;
  int totSeenSent;
  int totDataPktsRcvd; 
  int totOutofSeq; 
  int hsz; 
  
  /* basic control*/
  int epochTime; 
  int debug; 
  int verbose; 
  int initSession; 
  int initCapture; 
  int initFirewall;
  int initLroGro;
  int lroEnable;
  int groEnable;
  uint32_t ethFlags;
  char dev[IFNAMSIZ];
  int firewall_rule_number;
  char *filename;
  int maxpkts; 

  /* New loss-rate parameters */
  float loss_rate;
  float prop_delay;

  /* results are suspect for various reasons */
  int rtt_unreliable;
  int ignore_result;

  /* Drops and reordering startistics */
  int num_reordered;
  int num_unwanted_drops;
  int num_rtos;
  int num_reord_ret;
  int num_dup_transmissions;
  int num_dup_acks;
  int num_pkts_0_dup_acks;
  int num_pkts_1_dup_acks;
  int num_pkts_2_dup_acks;
  int num_pkts_3_dup_acks;
  int num_pkts_4_or_more_dup_acks;
  int num_dupack_ret;

  /* For PMTUD test */
  int mtu;

  /* For ByteCounting test */
  int bytecounting_type;
  int ack_bytes;  /* How many bytes covered per ACK */
  int ack_rate;   /* ACK [every | every other | every third |...] packet */

  /* For WindowScale Option test */
  uint8 receiving_shift_count;
  uint8 sending_shift_count;

  /* For MidBoxTTL test */
  int curr_ttl;

};

//void SendSessionPacket(struct IPPacket *packet, 
void SendSessionPacket(struct IPPacket *packet, 
		       uint16 ip_len, /* Total size of IP datagram */
		       uint8 tcp_flags,
		       uint16 ip_optlen, /* IP options len - New */
		       uint16 optlen,    /* TCP options len */
		       uint8 iptos);

void SendICMPReply(struct IPPacket *p);

void SendPkt(struct IPPacket *p, uint16 ip_len, int ip_optlen, int tcp_optlen);

void SendICMPPkt(struct ICMPUnreachableErrorPacket *p, uint16 ip_len);

void StorePacket (struct IPPacket *p); 

int EstablishSession(uint32 sourceAddress, \
		     uint16 sourcePort, \
		     uint32 targetAddress,
		     uint16 targetPort, \
		     int ip_optlen,\
		     char *ip_opt,\
		     int mss, 
		     int optlen, 
		     char *opt, \
		     int maxwin, 
		     int maxpkts, 
		     uint8 iptos, 
		     uint8 tcp_flags);

void rcvData (void (*ackData)(struct IPPacket *p)); 

void SendRequest(char *filename, void (*ackData)(struct IPPacket *p));

int  PrepareRequest(char *data, char *filename) ;
