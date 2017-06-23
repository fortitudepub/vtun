/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2008  Maxim Krasnyansky <max_mk@yahoo.com>

    VTun has been derived from VPPP package by Maxim Krasnyansky. 

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

/*
 * $Id: udp_proto.c,v 1.10.2.3 2009/03/29 10:09:13 mtbishop Exp $
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/udp.h>
#endif

#include "vtun.h"
#include "lib.h"

extern int is_rmt_fd_connected;

int kcpoudp_output_cb(const char *buf, int len, ikcpcb *kcp, void *user)
{
    struct vtun_host *host = user;
    int wlen;

    while (1) {
        if ((wlen = write(host->rmt_fd, buf, len)) < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }

            return -1;
        }

        return wlen;
    }
}

/* Functions to read/write UDP frames. */
int kcpoudp_write(int fd, char *buf, int len, struct vtun_host *host)
{
     register char *ptr;
     register int wlen;

     if (!is_rmt_fd_connected) return 0;

     // Presever vtun coding bit.
     ptr = buf - sizeof(short);

     *((unsigned short *)ptr) = htons(len);
     len  = (len & VTUN_FSIZE_MASK) + sizeof(short);

     if( (ikcp_send(host->kcp, ptr, len)) < 0 ) {
         // Do no propogate ikcp error.
	      return 0;
     }

     return 0;
}

int kcpoudp_fd_read(int fd, struct vtun_host *host)
{
     int packet_size = sizeof(short) + VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD;
     char tmp_buf[sizeof(short) + VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD];
     int rlen;
     unsigned short hdr, flen;
     struct sockaddr_in from;
     socklen_t fromlen = sizeof(struct sockaddr);

     /* Late connect (NAT hack enabled) */
     if (!is_rmt_fd_connected) {
          while( 1 ){
               if( (rlen = recvfrom(fd,tmp_buf,2,MSG_PEEK,(struct sockaddr *)&from,&fromlen)) < 0 ){ 
                    if( errno == EAGAIN || errno == EINTR ) continue;
                    else return rlen;
               }
               else break;
          }
          if( connect(fd,(struct sockaddr *)&from,fromlen) ){
               vtun_syslog(LOG_ERR,"Can't connect socket");
               return -1;
          }
          is_rmt_fd_connected = 1;
     }

     while( 1 ){
         // use mtu as udp packet size, can't be that bigger.
        if( (rlen = read(fd, tmp_buf, 1500)) < 0 ) {
	   if( errno == EAGAIN || errno == EINTR ) {
           continue;
       }
       return -1;
        }

        // drive the packet to ikcp.
        ikcp_input(host->kcp, tmp_buf, rlen);
        break;
	}

     return 0;
}

int kcpoudp_read(int fd, char *buf, struct vtun_host *host)
{
     int packet_size = sizeof(short) + VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD;
     char tmp_buf[sizeof(short) + VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD];
     int rlen;
     unsigned short hdr, flen;

     // seems kcp is datagram protocol, emulation of stream protocol
     // is not enabled (see kcp->stream.).

     // read packet header and read length.
     if ((rlen = ikcp_recv(host->kcp, tmp_buf, packet_size)) < 0) {
         // we should convert it to harmless value to let linkerfd
         // continue to operate.
         return VTUN_ECHO_REP;
     }

     // extract frame length from encoded length.
     hdr = ntohs(*(unsigned short *)(&tmp_buf[0]));
     flen = hdr & VTUN_FSIZE_MASK;

     if( rlen < 2 || (rlen-2) != flen ) {
         return VTUN_BAD_FRAME;
     }

     // skip hdr bit and copy FULL data FRAME...
     memcpy(buf, ((char *)&tmp_buf) + 2, flen);

     return hdr;
}

int kcpoudp_update(struct vtun_host *host, unsigned int now_in_ms) {
    ikcp_update(host->kcp, now_in_ms);
    return 0;
}
