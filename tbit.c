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

#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "base.h"
#include "inet.h"
#include "capture.h"
#include "support.h"
#include "tbit.h"
#include "reno.h"
#include "session.h"
#include "sack.h"
#include "tahoe_no_fr_check.h"
#include "windowhalf.h"
#include "new_windowhalf.h"
#include "ecn.h"
#include "new_ecn.h"
#include "ecn_iponly.h"
#include "sack_rcvr.h"
#include "initwin.h"
#include "delack.h"
#include "timewait.h"
#include "ini_rto.h"
#include "piggyfin.h"
#include "sack_sndr_3p.h"
#include "totdata.h"
#include "flags.h"
#include "loss_rate.h"
#include "pmtud.h"
#include "bytecounting.h"
#include "bc_slowstart.h"
#include "bc_slowstart_icw_1.h"
#include "bc_slowstart_icw_2.h"
#include "bc_slowstart_icw_3.h"
#include "bc_slowstart_icw_4.h"
#include "windowscale.h"
#include "reordering.h"
#include "ipoptions_rr_syn.h"
#include "ipoptions_ts_syn.h"
#include "ipoptions_faked_syn.h"
#include "ipoptions_faked_mid.h"
#include "tcpoptions_faked_syn.h"
#include "tcpoptions_faked_mid.h"
#include "tcpoptions_timestamp_syn.h"
#include "tcpoptions_timestamp_mid.h"
#include "limited_transmit.h"
#include "limited_transmit_icw_1.h"
#include "limited_transmit_icw_2.h"
#include "limited_transmit_icw_3.h"
#include "limited_transmit_icw_4.h"
#include "icw_perf.h"
#include "min_rto.h"
#include "totdataRST.h"
#include "rwnd_icw.h"
#include "midbox_ttl.h"
#include "blackhole.h"
#include "general_perf.h"
#include "test_one_byte_req.h"
#include "dup_acks.h"
#include "reord_ret.h"
#include "dsack.h"
#include "window_buildup.h"

extern char *optarg; /* Variables used for getopt(3) */
extern int optind;
extern int opterr;
extern int optopt;
extern struct TcpSession session; 

enum test_id {
  NO_TEST,
  SACK,
  RENO,
  TAHOE_NO_FR,
  WINHALF,
  NEW_WINHALF,
  ECN,
  ECN_IPONLY,
  SACK_RCVR,
  INITWIN,
  DELACK,
  TIMEWAIT,
  IniRTO,
  PIGGY_FIN,
  SACK_SNDR_3P,
  TOTDATA,
  FLAGS,
  NEW_ECN,
  LOSS_RATE,
  PMTUD,
  REORDERING,
  BYTECOUNTING,
  BYTECOUNTING_ICW_1,
  BYTECOUNTING_ICW_2,
  BYTECOUNTING_ICW_3,
  BYTECOUNTING_ICW_4,
  WINDOW_SCALE,
  TCP_FAKED_SYN_OPT,
  TCP_FAKED_MIDDLE_OPT,
  IP_RR_OPT,
  IP_TS_OPT,
  IP_FAKED_SYN_OPT,
  IP_FAKED_MIDDLE_OPT,
  TIMESTAMP_SYN_OPT,
  TIMESTAMP_MIDDLE_OPT,
  LIMITED_TRANSMIT,
  LIMITED_TRANSMIT_ICW_1,
  LIMITED_TRANSMIT_ICW_2,
  LIMITED_TRANSMIT_ICW_3,
  LIMITED_TRANSMIT_ICW_4,
  ICW_PERFORMANCE_1,
  ICW_PERFORMANCE_2,
  MIN_RTO,
  TOTDATA_RST,
  RWND_ICW,
  MIDBOX_TTL,
  BLACKHOLE,
  GENERAL_PERFORMANCE,
  ONE_BYTE_REQ,
  DUP_ACKS,
  REORD_RET,
  DSACK,
  WINDOW_BUILDUP,
  LAST_TEST_ID /* do not (re)move this */
};

void usage(char *progname);
int FindDeviceName(uint32_t sourceIpAddr);
int GetCannonicalInfo(char *string, char name[MAXHOSTNAMELEN], uint32 *address);
int BindTcpPort(int sockfd) ; 

int main(int argc, char **argv) 
{

  uint32 targetIpAddress;		/* IP address of target host */
  uint16 targetPort = DEFAULT_TARGETPORT;
  
  char source[MAXHOSTNAMELEN];
  uint32 sourceIpAddress = 0;
  uint16 sourcePort = 0;
  
  int mss = DEFAULT_MSS; 
  int mtu = DEFAULT_MTU;

  int bytecounting_type = 0;
  int ack_rate = 1;
  int ack_bytes = 0;

  struct sockaddr_in saddr;
  int fd ; 
  int opt;
  int testid = NO_TEST ; 
  uint8 flags = 0; 

  /* init the random number generator */
  srand48(GetTimeMicroSeconds());

  opterr = 0;
  bzero(session.targetName, MAXHOSTNAMELEN);
  while ((opt = getopt(argc, argv, "n:p:m:M:w:h:f:s:t:r:D:a:b:S:P:c:dv")) != EOF) {

    switch (opt) {

    case 'n':
      /* server host name */
      strncpy(session.targetName, optarg, MAXHOSTNAMELEN);
      break;

    case 'p':
      /* server port */
      targetPort = atoi(optarg);
      break;

    case 'm':
      /* max segment size negotiatedd by TBIT */
      mss = atoi(optarg);
      break;

    case 'M':
      /* MTU size - for PMTUD test */
      mtu = atoi(optarg);
      break;

    case 'w':
      /* port used by TBIT */
      sourcePort = atoi(optarg);
      break;

    case 'h':	
      /* URL to download */
      if ((session.filename = (char *)calloc(sizeof(char), strlen(optarg) + 1)) == NULL) {
	perror("ERROR: no buffer for filename:");
	Quit(ERR_MEM_ALLOC) ; 
      }
      strcpy (session.filename, optarg);
      break ;

    case 'f':
      /* TCP flags */
      flags = (uint8)atoi(optarg);
      break;

    case 's':
      /* IP address of TBIT's machine */
      strncpy(source, optarg, MAXHOSTNAMELEN); 
      sourceIpAddress = 1;
      break;

    case 't':

      /* Test to be executed */
      if (strcmp(optarg, "Reno") == 0) {testid = RENO; break;}
      if (strcmp(optarg, "Sack") == 0) {testid = SACK; break;}
      if (strcmp(optarg, "TahoeNoFR") == 0) {testid = TAHOE_NO_FR; break;}
      if (strcmp(optarg, "WinHalf") == 0) {testid = WINHALF; break;}
      if (strcmp(optarg, "NewWinHalf") == 0) {testid = NEW_WINHALF; break;}
      if (strcmp(optarg, "ECN") == 0) {testid = ECN; break;}
      if (strcmp(optarg, "ECN_IPOnly")==0) {testid = ECN_IPONLY; break;}
      if (strcmp(optarg, "SackRcvr") == 0) {testid = SACK_RCVR; break;}
      if (strcmp(optarg, "InitWin") == 0) {testid = INITWIN; break;}
      if (strcmp(optarg, "DelAck") == 0) {testid = DELACK; break;}
      if (strcmp(optarg, "TimeWait") == 0) {testid = TIMEWAIT; break;}
      if (strcmp(optarg, "IniRTO") == 0) {testid = IniRTO; break;}
      if (strcmp(optarg, "PiggyFIN") == 0) {testid = PIGGY_FIN; break;}
      if (strcmp(optarg, "SackSndr3P") == 0) {testid = SACK_SNDR_3P; break;}
      if (strcmp(optarg, "TotData") == 0) {testid = TOTDATA; break;}
      if (strcmp(optarg, "Flags") == 0) {testid = FLAGS; break;}
      if (strcmp(optarg, "NewECN") == 0) {testid = NEW_ECN; break;}
      if (strcmp(optarg, "LossRate") == 0) {testid = LOSS_RATE; break;}
      if (strcmp(optarg, "PMTUD") == 0) {testid = PMTUD; break;}
      if (strcmp(optarg, "ByteCounting") == 0) {testid = BYTECOUNTING; break;}
      if (strcmp(optarg, "ByteCountingICW1") == 0) {testid = BYTECOUNTING_ICW_1; break;}
      if (strcmp(optarg, "ByteCountingICW2") == 0) {testid = BYTECOUNTING_ICW_2; break;}
      if (strcmp(optarg, "ByteCountingICW3") == 0) {testid = BYTECOUNTING_ICW_3; break;}
      if (strcmp(optarg, "ByteCountingICW4") == 0) {testid = BYTECOUNTING_ICW_4; break;}
      if (strcmp(optarg, "WindowScale") == 0) {testid = WINDOW_SCALE; break;}
      if (strcmp(optarg, "Reordering") == 0) {testid = REORDERING; break;}
      if (strcmp(optarg, "IPRRSynOption") == 0) {testid = IP_RR_OPT; break;}
      if (strcmp(optarg, "IPTSSynOption") == 0) {testid = IP_TS_OPT; break;}
      if (strcmp(optarg, "IPFakedSynOption") == 0) {testid = IP_FAKED_SYN_OPT; break;}
      if (strcmp(optarg, "IPFakedMiddleOption") == 0) {testid = IP_FAKED_MIDDLE_OPT; break;}
      if (strcmp(optarg, "TCPFakedSynOption") == 0) {testid = TCP_FAKED_SYN_OPT; break;}
      if (strcmp(optarg, "TCPFakedMiddleOption") == 0) {testid = TCP_FAKED_MIDDLE_OPT; break;}
      if (strcmp(optarg, "TCPTimestampSynOption") == 0) {testid = TIMESTAMP_SYN_OPT; break;}
      if (strcmp(optarg, "TCPTimestampMiddleOption") == 0) {testid = TIMESTAMP_MIDDLE_OPT; break;}
      if (strcmp(optarg, "LimitedTransmit") == 0) {testid = LIMITED_TRANSMIT; break;}
      if (strcmp(optarg, "LimitedTransmitICW1") == 0) {testid = LIMITED_TRANSMIT_ICW_1; break;}
      if (strcmp(optarg, "LimitedTransmitICW2") == 0) {testid = LIMITED_TRANSMIT_ICW_2; break;}
      if (strcmp(optarg, "LimitedTransmitICW3") == 0) {testid = LIMITED_TRANSMIT_ICW_3; break;}
      if (strcmp(optarg, "LimitedTransmitICW4") == 0) {testid = LIMITED_TRANSMIT_ICW_4; break;}
      if (strcmp(optarg, "ICWPerformance_1") == 0) {testid = ICW_PERFORMANCE_1; break;}
      if (strcmp(optarg, "ICWPerformance_2") == 0) {testid = ICW_PERFORMANCE_2; break;}
      if (strcmp(optarg, "MinRTO") == 0) {testid = MIN_RTO; break;}
      if (strcmp(optarg, "TotDataRST") == 0) {testid = TOTDATA_RST; break;}
      if (strcmp(optarg, "RwndICW") == 0) {testid = RWND_ICW; break;}
      if (strcmp(optarg, "MidBoxTTL") == 0) {testid = MIDBOX_TTL; break;}
      if (strcmp(optarg, "BlackHole") == 0) {testid = BLACKHOLE; break;}
      if (strcmp(optarg, "GenPerf") == 0) {testid = GENERAL_PERFORMANCE; break;}
      if (strcmp(optarg, "OneByteReq") == 0) {testid = ONE_BYTE_REQ; break;}
      if (strcmp(optarg, "DupAcks") == 0) {testid = DUP_ACKS; break;}
      if (strcmp(optarg, "ReordRet") == 0) {testid = REORD_RET; break;}
      if (strcmp(optarg, "DSack") == 0) {testid = DSACK; break;}
      if (strcmp(optarg, "WindowBuildUp") == 0) {testid = WINDOW_BUILDUP; break;}

      
      break;

    case 'S':
      /* ByteCounting test in "security" mode (-S) */
      if (atoi(optarg) < 1  || atoi(optarg) > 2) {
	printf ("ERROR: Wrong ByteCounting Security mode option!\n");
	Quit(BAD_ARGS);
      }
      bytecounting_type = atoi(optarg);
      break;

    case 'P':
      /* ByteCounting test in "performance" mode (-P: 1) */
      if (atoi(optarg) < 1  || atoi(optarg) > 2) {
	printf ("ERROR: Wrong ByteCounting Performance mode option!\n");
	Quit(BAD_ARGS);
      }
      bytecounting_type = 2 + atoi(optarg);
      break;

    case 'a':
      /* "Generic" ByteCounting test in "performance" mode (-a: ack "spacing") */
      ack_rate = atoi(optarg);
      break;

    case 'b':
      /* "Generic" ByteCounting test in "security" mode (-b: bytes covered by each ACK */
      ack_bytes = atoi(optarg);
      break;

    case 'r':
      /* Session loss rate */
      session.loss_rate = atof(optarg);
      break;

    case 'c':
      session.sending_shift_count = atoi(optarg);
      break;

    case 'D':
      /* session propagation delay */
      session.prop_delay = atof(optarg);
      break;

    case 'd':
      /* print debug info flag */
      session.debug = 1 ;
      break;

    case 'v':
      /* verbose execution mode */
      session.verbose = 1 ;
      break;

    default:

      usage (argv[0]);
      Quit(BAD_ARGS);
      break ;

    }
  }

  switch (argc - optind) {
  case 1:
    if (strlen(argv[optind]) > MAXHOSTNAMELEN - 1) {
      printf ("host name too long\n");
      Quit(NO_TRGET_SPECIFIED);
    }
    break;

  default:
    usage(argv[0]);
    printf("No target specified\nRETURN CODE: %d\n", 
	   NO_TRGET_SPECIFIED);
    Quit(NO_TRGET_SPECIFIED);
  }
  
  /* set up signal handlers to exit cleanly */
  signal(SIGTERM, SigHandle);
  signal(SIGINT, SigHandle);
  signal(SIGHUP, SigHandle);
  
  /* Get hostname and IP address of target host */
  if (GetCannonicalInfo(argv[optind], session.targetHostName, &targetIpAddress) < 0) {
    Quit(NO_TARGET_CANON_INFO);
  }
  
  /* Get hostname and IP address of source host */
  if (sourceIpAddress == 0) {
    if (gethostname(source, MAXHOSTNAMELEN) != 0) {
      printf("ERROR: can't determine local hostname\n");
      Quit(NO_LOCAL_HOSTNAME);
    }
  }
  
  if (GetCannonicalInfo(source, session.sourceHostName, &sourceIpAddress) < 0) {
    Quit(NO_SRC_CANON_INFO);
  }

  /* Find the device name corresponding to the source IP address */
  if (FindDeviceName(sourceIpAddress) < 0) {
    Quit(NO_DEVICE_NAME);
  }

  if (sourcePort == 0) {

    /* Find and allocate a spare TCP port to use */
    saddr.sin_family = AF_INET;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      printf("ERROR: can't open socket\n");
      return -1 ;
    }

    if ((sourcePort = BindTcpPort(fd)) == 0) {
      printf("ERROR: can't bind port\n");
      return -1;
    }

  }

  if (session.debug) {
    printf("source = %s [%s] (%0x) port = %d\n",\
	   session.sourceHostName, InetAddress(sourceIpAddress), 
	   sourceIpAddress, sourcePort);
    printf("target = %s [%s] (%0x) port = %d\n",\
	   session.targetHostName, InetAddress(targetIpAddress), 
	   targetIpAddress, targetPort);
  }
  
  /* Init packet capture device and install filter for our flow */
  /* Filter will be associated with transmitted packets*/
  CaptureInit(sourceIpAddress, sourcePort, targetIpAddress, targetPort);
  session.initCapture = 1;
  
  /* Reset LRO, GRO */
  ResetLroGro();
  session.initLroGro = 1;

  session.rtt_unreliable = 0;
  session.num_reordered = 0;

  switch (testid) {

  case NO_TEST: 
    printf ("No test specified.\n");
    Quit(BAD_ARGS); 
    break; 

  case SACK:
    SackTest (sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case RENO:
    RenoTest (sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case TAHOE_NO_FR: 
    TahoeNoFRTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case WINHALF: 
    WindowHalfTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case NEW_WINHALF: 
    NewWindowHalfTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case ECN: 
    ECNTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case ECN_IPONLY: 
    ECN_IPONLYTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case SACK_RCVR: 
    SackRcvrTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case INITWIN: 
    InitWinTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case DELACK: 
    DelAckTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case TIMEWAIT: 
    TimeWaitTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case IniRTO: 
    IniRTOTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case PIGGY_FIN: 
    PiggyFINTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case SACK_SNDR_3P: 
    SackSndr3PTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case TOTDATA: 
    TotDataTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case FLAGS: 
    FlagsTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss, flags);
    break ; 

  case NEW_ECN: 
    NewECNTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case LOSS_RATE: 
    LossRateTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case PMTUD: 
    PMTUDTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss, mtu);
    break;

  case REORDERING: 
    ReorderingTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case BYTECOUNTING: 

    printf("BC T: %d\n", bytecounting_type);
    if (bytecounting_type == 0) {
      bytecounting_type = PERFORMANCE_MODE_SLOWSTART;
    }

    switch (bytecounting_type) {
      
    case SECURITY_MODE_GENERIC:
      ack_rate = 1;
      if (ack_bytes == 0) {
	ack_bytes = mss;
      } 
      ByteCountingTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss, bytecounting_type, ack_rate, ack_bytes);
      break;

    case PERFORMANCE_MODE_GENERIC:      
      ack_bytes = mss;
      if (ack_rate == 0) {
	ack_rate = 1;
      }
      ByteCountingTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss, bytecounting_type, ack_rate, ack_bytes);
      break;

    case PERFORMANCE_MODE_SLOWSTART:      
      BCSlowStartTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
      break;

    default:
      usage (argv[0]);
      Quit(BAD_ARGS);
      
    }
    break;

  case BYTECOUNTING_ICW_1:      

    bytecounting_type = PERFORMANCE_MODE_SLOWSTART;
    BCSlowStartICW1Test(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case BYTECOUNTING_ICW_2:      

    bytecounting_type = PERFORMANCE_MODE_SLOWSTART;

    BCSlowStartICW2Test(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case BYTECOUNTING_ICW_3:      

    bytecounting_type = PERFORMANCE_MODE_SLOWSTART;

    BCSlowStartICW3Test(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case BYTECOUNTING_ICW_4:      

    bytecounting_type = PERFORMANCE_MODE_SLOWSTART;

    BCSlowStartICW4Test(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case WINDOW_SCALE: 
    WindowScaleTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case IP_RR_OPT:
    IPRROptionTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case IP_TS_OPT:
    IPTSOptionTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case IP_FAKED_SYN_OPT:
    IPFakedOptionSYNTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case IP_FAKED_MIDDLE_OPT:
    FakedMiddleIPOptionTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case TCP_FAKED_SYN_OPT:
    FakedSynTCPOptionTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case TCP_FAKED_MIDDLE_OPT:
    FakedMiddleTCPOptionTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case TIMESTAMP_SYN_OPT: 
    TimestampSynTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case TIMESTAMP_MIDDLE_OPT: 
    TimestampMiddleTCPOptionTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break ; 

  case LIMITED_TRANSMIT:
    LimitedTransmitTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case LIMITED_TRANSMIT_ICW_1:
    LimitedTransmit_ICW_1_Test(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case LIMITED_TRANSMIT_ICW_2:
    LimitedTransmit_ICW_2_Test(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case LIMITED_TRANSMIT_ICW_3:
    LimitedTransmit_ICW_3_Test(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case LIMITED_TRANSMIT_ICW_4:
    LimitedTransmit_ICW_4_Test(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case ICW_PERFORMANCE_1:
    ICWPerformanceTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss, 1);
    break;

  case ICW_PERFORMANCE_2:
    ICWPerformanceTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss, 2);
    break;

  case MIN_RTO:
    MinRTOTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case TOTDATA_RST:
    TotDataRSTTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case RWND_ICW:
    RwndICWTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case MIDBOX_TTL:
    MidBoxTTLTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case BLACKHOLE:
    BlackHoleDetectionTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss, mtu);
    break;

  case GENERAL_PERFORMANCE:
    GeneralPerformanceTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case ONE_BYTE_REQ:
    OneByteReqTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case DUP_ACKS:
    DupAcksTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case REORD_RET:
    ReordRetTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case DSACK:
    DuplicateSackTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  case WINDOW_BUILDUP:
    WindowBuildUpTest(sourceIpAddress, sourcePort, targetIpAddress, targetPort, mss);
    break;

  default: 
    usage (argv[0]);
    Quit(BAD_ARGS);
  }

  Cleanup(0);
  close(session.socket); 

  return(0);

}

void usage (char *progname) {
  printf("%s ", progname);
  printf("\t[-d] \n\t[-v] \n\t[-n <hostname>] \n\t[-m <pktsz>] \n\t[-M <MTU>] \n\t[-p <target port>]");
  printf("\n\t[-w <sourceport>] \n\t[-h <url>] \n\t[-f flags>] \n\t[-b <acked bytes>] \n\t[-a <ack spacing>]");
  printf("\n\t[-S] \n\t[-P]");
  printf("\n\t-t \n\t\t<Reno | \n\t\tSack | \n\t\tTimestamp | \n\t\tTahoeNoFR | \n\t\tWinHalf | \n\t\tInitWin | \n\t\tECN |");
  printf("\n\t\tECN_IPOnly | \n\t\tSackRcvr | \n\t\tDelAck | \n\t\tTimeWait | \n\t\tIniRTO | \n\t\tPiggyFIN | \n\t\tSackSndr3P |");
  printf("\n\t\tTotData | \n\t\tFlags | \n\t\tNewECN |\n\t\tLossRate | \n\t\tPMTUD>");
  printf("\n\t<hostname | ipaddr>\n");
}

int FindDeviceName(uint32_t sourceIpAddress)
{
  struct ifaddrs *ifs, *i;

  if (getifaddrs(&ifs) < 0) {
    perror("ERROR: cannot list interfaces");
    return -1;
  }

  for (i = ifs; i != NULL; i = i->ifa_next) {
    struct sockaddr_in *addr = (struct sockaddr_in *)i->ifa_addr;
    if (addr->sin_addr.s_addr == sourceIpAddress) {
      break;
    }
  }

  if (i != NULL) {
    strncpy(session.dev, i->ifa_name, IFNAMSIZ);
    freeifaddrs(ifs);
    return 0;
  }

  freeifaddrs(ifs);
  return -1;
}

int GetCannonicalInfo(char *string, char name[MAXHOSTNAMELEN], uint32 *address)
{
  struct hostent *hp;

  /* Is string in dotted decimal format? */
  if ((*address = inet_addr(string)) == INADDR_NONE) {

    /* No, then lookup IP address */
    if ((hp = gethostbyname(string)) == NULL) {

      /* Can't find IP address */
      printf("ERROR: Couldn't obtain address for %s\nRETURN CODE: %d\n", 
	     string, FAIL);
      return -1;

    } else {

      strncpy(name, hp->h_name, MAXHOSTNAMELEN-1);
      memcpy((void *)address, (void *)hp->h_addr, hp->h_length);

    }
  } else {
    if ((hp = gethostbyaddr((char *)address, sizeof(*address), AF_INET)) == NULL) {
      /* Can't get cannonical hostname, so just use input string */
      if (session.debug) {
	printf("WARNING: Couldn't obtain cannonical name for %s\nRETURN CODE: %d", 
	       string, NO_SRC_CANON_INFO);
      }
      strncpy(name, string, MAXHOSTNAMELEN - 1);
    } else {
      strncpy(name, hp->h_name, MAXHOSTNAMELEN - 1);
    }
  }
  return 0;
}

int BindTcpPort(int sockfd)
{
  struct sockaddr_in	sockName;
  int port, result;
  int randomOffset;

#define START_PORT (10*1024) 
#define END_PORT   (0xFFFF)

  /* Choose random offset to reduce likelihood of collision with last run */
  randomOffset = (int)(1000.0*drand48());

  /* Try to find a free port in the range START_PORT+1..END_PORT */
  port = START_PORT+randomOffset;
  do {

    ++port;
    sockName.sin_addr.s_addr = INADDR_ANY;			 
    sockName.sin_family = AF_INET;
    sockName.sin_port = htons(port);
    result = bind(sockfd, (struct sockaddr *)&sockName,
		  sizeof(sockName));
  } while ((result < 0) && (port < END_PORT));
	 
  if (result < 0) {
    /* No free ports */
    perror("bind");
    port = 0;
  }	
 
  return port;

}
