# Copyright (c) 2000, 2001 
# International Computer Science Institute
# All rights reserved.
#
# This file may contain software code originally developed 
# for the Sting project. The Sting software carries the following copyright:
#
# Copyright (c) 1998, 1999
# Stefan Savage and the University of Washington.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgment:
#      This product includes software developed by ACIRI, the AT&T
#      Center for Internet Research at ICSI (the International Computer
#      Science Institute). This product may also include software developed
#      by Stefan Savage at the  University of Washington. 
# 4. The names of ACIRI, ICSI, Stefan Savage and University of Washington
#    may not be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY ICSI AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL ICSI OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

SRC = tbit.c inet.c capture.c gmt2local.c support.c session.c history.c \
	sack.c \
	tahoe_no_fr_check.c \
	windowhalf.c \
	new_windowhalf.c \
	ecn.c \
	ecn_iponly.c initwin.c delack.c timewait.c \
	ini_rto.c piggyfin.c totdata.c flags.c \
	reno.c 	\
	sack_rcvr.c \
	sack_sndr_3p.c 	\
	new_ecn.c\
	loss_rate.c\
	pmtud.c\
	bytecounting.c \
	reordering.c\
	bc_slowstart.c \
	bc_slowstart_icw_1.c \
	bc_slowstart_icw_2.c \
	bc_slowstart_icw_3.c \
	bc_slowstart_icw_4.c \
	windowscale.c \
	ipoptions_rr_syn.c \
	ipoptions_ts_syn.c \
	ipoptions_faked_syn.c \
	ipoptions_faked_mid.c \
	tcpoptions_faked_syn.c \
	tcpoptions_faked_mid.c \
	tcpoptions_timestamp_syn.c \
	tcpoptions_timestamp_mid.c \
	limited_transmit.c \
	limited_transmit_icw_1.c \
	limited_transmit_icw_2.c \
	limited_transmit_icw_3.c \
	limited_transmit_icw_4.c \
	icw_perf.c \
	min_rto.c \
	totdataRST.c \
	rwnd_icw.c \
	midbox_ttl.c \
	blackhole.c \
	general_perf.c \
	test_one_byte_req.c \
	dup_acks.c \
	reord_ret.c \
	dsack.c \
	window_buildup.c

LIBPCAP = ./libpcap-0.4
CC = gcc 
OBJS = version.o $(SRC:.c=.o)
INCLS = -I.
DEFS = -DRETSIGTYPE=void -DHAVE_SIGACTION=1  -DTIME_WITH_SYS_TIME=1
CFLAGS =  -g -Wall $(CCOPT) $(DEFS) $(INCLS)
LIBS = -lm -lpcap

all: tbit 

version.o: version.c
version.c: VERSION
	@rm -f $@
	sed -e 's/.*/char tbit_version[] = "&";/' VERSION > $@

.s.o:
	@rm -f $@
	$(CC) $(CFLAGS) -c $*.c

tbit: $(OBJS) $(LIBS)
	@rm -f $@
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	-rm -f $(OBJS) tbit

depend:
	mkdep ${CFLAGS} ${SRC}
