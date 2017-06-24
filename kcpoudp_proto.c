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

#include "pthread.h"

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
int kcpoudp_write(char *buf, int len, struct vtun_host *host)
{
     register char *ptr;
     register int wlen;

     if (!is_rmt_fd_connected) return 0;

     // Presever vtun coding bit.
     ptr = buf - sizeof(short);

     *((unsigned short *)ptr) = htons(len);
     len  = (len & VTUN_FSIZE_MASK) + sizeof(short);

     //pthread_mutex_lock(&host->kcp_lock);
     if( (ikcp_send(host->kcp, ptr, len)) < 0 ) {
         // Do no propogate ikcp error.
         //pthread_mutex_unlock(&host->kcp_lock);
         return 0;
     }

     // flush asap.
     /* { */
     /*     long ms; */
     /*     time_t s; */
     /*     struct timespec spec; */
     /*     clock_gettime(CLOCK_REALTIME, &spec); */
     /*     s = spec.tv_sec; */
     /*     ms = round(spec.tv_nsec/1000000); */
     /*     // use current ms to drive the kcp. */
     /*     ikcp_update(host->kcp, s*100+ms); */
     /* } */
     // flush immediately.
     ikcp_flush(host->kcp);

     //pthread_mutex_unlock(&host->kcp_lock);
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

     // No nat hack is needed in our service.
     /* /\* Late connect (NAT hack enabled) *\/ */
     /* if (!is_rmt_fd_connected) { */
     /*      while( 1 ){ */
     /*           if( (rlen = recvfrom(fd,tmp_buf,2,MSG_PEEK,(struct sockaddr *)&from,&fromlen)) < 0 ){  */
     /*                if( errno == EAGAIN || errno == EINTR ) continue; */
     /*                else return rlen; */
     /*           } */
     /*           else break; */
     /*      } */
     /*      if( connect(fd,(struct sockaddr *)&from,fromlen) ){ */
     /*           vtun_syslog(LOG_ERR,"Can't connect socket"); */
     /*           return -1; */
     /*      } */
     /*      is_rmt_fd_connected = 1; */
     /* } */

     while( 1 ){
         // use mtu as udp packet size, can't be that bigger.
        if( (rlen = read(fd, tmp_buf, 1500)) < 0 ) {
	   if( errno == EAGAIN || errno == EINTR ) {
           continue;
       }
       return -1;
        }

        // drive the packet to ikcp.
        //pthread_mutex_lock(&host->kcp_lock);
        ikcp_input(host->kcp, tmp_buf, rlen);
        //pthread_mutex_unlock(&host->kcp_lock);
        break;
	}

     return 0;
}

// kcp->stream == 0, default mode.
int kcpoudp_read(char *buf, struct vtun_host *host) {
     char tmp_buf[1500];
     int rlen;
     unsigned short hdr, flen;

     //pthread_mutex_lock(&host->kcp_lock);
     // use mtu is enough.
     if ((rlen = ikcp_recv(host->kcp, tmp_buf, 1500)) < 0) {
         // we should convert it to harmless value to let linkerfd
         // continue to operate.
         //pthread_mutex_unlock(&host->kcp_lock);
         return VTUN_ECHO_REP;
     }
     //pthread_mutex_unlock(&host->kcp_lock);

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

#if 0
// kcp->stream == 1, default is 0.
int kcpoudp_read_stream(char *buf, struct vtun_host *host)
{
     static unsigned int unread_bytes = 0;
     static char static_buf[65535];
     char tmp_buf[65535];
     int rlen;
     unsigned short hdr, flen, peek_size;

     // HANDLE KCP STREAM PROTOCOL, RECOVER IP PACKTS.
     // 1. 先peek 2字节，根据peek出来的结果取出ip packet frame len，然后再去
     //    peek，如果够则读，不够等下次
     // 2. 够的情况下，读出的buffer可能会存在余量，下次先基于余量提取，不够
     //    的话按1的方式处理
     // 这样最多记录一点当前多出来的buffer，不会过多

     pthread_mutex_lock(&host->kcp_lock);

     if (unread_bytes) {
         if (unread_bytes > 2) {
             hdr = ntohs(*(unsigned short *)(&static_buf[0]));
             flen = hdr & VTUN_FSIZE_MASK;
             if (unread_bytes >= (2 + flen)) { // 残留足够一个包
                 // 有一个完整包，拷贝到上层内存中待返回
                 if (flen !=0 ){
                     memcpy(buf, ((char *)&static_buf) + 2, flen);
                 } else {
                     // REQ包，无包体，只有hdr
                 }

                 // 这里没法共享下面的逻辑，因为要调整static buf
                 unread_bytes -= 2 + flen;
                 if (unread_bytes) {
                     memmove((char *)static_buf, ((char*)static_buf) + 2, unread_bytes);                     
                 }
                 pthread_mutex_unlock(&host->kcp_lock);
                 return hdr;
             } else { // 残留不足一个包
                 peek_size = (2 + flen) - unread_bytes;
             }
         } else {
             // 余了1个字节，这个非常特殊，要peek一字节后再拼起来
             // 保存之，tmp_buf将被改写
             rlen = ikcp_recv(host->kcp, tmp_buf, -1);
             if ((rlen != -3) && (rlen < 1)) {
                 // 包不够长，等下一轮
                 pthread_mutex_unlock(&host->kcp_lock);
                 return VTUN_ECHO_REP;
             }
             tmp_buf[1] = tmp_buf[0];
             tmp_buf[0] = static_buf[0];
             hdr = ntohs(*(unsigned short *)(&tmp_buf[0]));
             flen = hdr & VTUN_FSIZE_MASK;
             peek_size = flen + 1;
         }

         // peek at least contain a header.
         rlen = ikcp_recv(host->kcp, tmp_buf, -peek_size);
         if ((rlen != -3) && (rlen < peek_size)) {
             // 包不够长，等下一轮
             pthread_mutex_unlock(&host->kcp_lock);
             return VTUN_ECHO_REP;
         }

         // peek size可能会增长，所以这里用个最大可能的buffer来读取之
         if ((rlen = ikcp_recv(host->kcp, tmp_buf, 65535)) < 0) {
             // MUST BE WRONG, PEEK HAVE TELL US.
             pthread_mutex_unlock(&host->kcp_lock);
             return VTUN_ECHO_REP;
         }

         if (flen == 0) {
             // REQ只有头
         } else {
             // 拼出完整包给上层
             if (unread_bytes > 2) {
                 // 把上次残留的数据的报文用过来
                 memcpy(buf, (char*)static_buf + 2, unread_bytes - 2);
                 memcpy(buf + unread_bytes - 2, ((char *)&tmp_buf), rlen - peek_size);
             } else { //余1个字节的特殊情况
                 memcpy(buf, ((char *)&tmp_buf) + 1, flen);
             }
         }
         // 重新填冲static buf
         unread_bytes = rlen - peek_size;
         // 把未读的内存移到static_buf起始，以便下次进来读取
         if (unread_bytes) {
             memcpy((char *)static_buf, ((char*)tmp_buf) + peek_size, unread_bytes);
         }

         pthread_mutex_unlock(&host->kcp_lock);
         return hdr;
     } else { // 上次无残留
         // peek直至存在有大于包头（2）的长度
         rlen = ikcp_recv(host->kcp, tmp_buf, -2);
         if ((rlen != -3) && (rlen < 2)) {
             // 包不够长，等下一轮
             pthread_mutex_unlock(&host->kcp_lock);
             return VTUN_ECHO_REP;
         }

         // 用peek调用时回填的buf解码出报文长度，然后二次peek
         // 如果peek到则读回
         hdr = ntohs(*(unsigned short *)(&tmp_buf[0]));
         flen = hdr & VTUN_FSIZE_MASK;
         // peek at least contain a header.
         peek_size = 2 + flen;
         rlen = ikcp_recv(host->kcp, tmp_buf, -peek_size);
         if ((rlen != -3) && (rlen < peek_size)) {
             // 包不够长，等下一轮
             pthread_mutex_unlock(&host->kcp_lock);
             return VTUN_ECHO_REP;
         }

         // peek size可能会增长，所以这里用个最大可能的buffer来读取之
         if ((rlen = ikcp_recv(host->kcp, tmp_buf, 65535)) < 0) {
             // MUST BE WRONG, PEEK HAVE TELL US.
             pthread_mutex_unlock(&host->kcp_lock);
             return VTUN_ECHO_REP;
         }

         if (flen == 0) {
             // 无消息体如REQ，无需拷贝数据
         } else {
             // 有一个带数据的包，拷贝到上层内存中待返回
             memcpy(buf, ((char *)&tmp_buf) + 2, flen);
         }
         // 被peek走的数据都用掉了
         unread_bytes = rlen - peek_size;
         // 把未读的内存移到static_buf起始，以便下次进来读取
         if (unread_bytes) {
             memcpy((char *)static_buf, ((char*)tmp_buf) + peek_size, unread_bytes);
         }

         pthread_mutex_unlock(&host->kcp_lock);
         return hdr;
     }
}
#endif

int kcpoudp_update(struct vtun_host *host, unsigned int now_in_ms) {
    //pthread_mutex_lock(&host->kcp_lock);
    ikcp_update(host->kcp, now_in_ms);
    //pthread_mutex_unlock(&host->kcp_lock);
    return 0;
}
