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
 * $Id: driver.h,v 1.4.2.2 2008/01/07 22:35:30 mtbishop Exp $
 */ 
#ifndef _DRIVER_H
#define _DRIVER_H

/* Definitions for device and protocol drivers 
 * Interface will be completely rewritten in 
 * version 3.0
 */

extern int (*dev_write)(int fd, char *buf, int len);
extern int (*dev_read)(int fd, char *buf, int len);

extern int (*proto_write)(int fd, char *buf, int len);
extern int (*proto_read)(int fd, char *buf);

int tun_open(char *dev);
int tun_close(int fd, char *dev);
int tun_write(int fd, char *buf, int len);
int tun_read(int fd, char *buf, int len);

int tap_open(char *dev);
int tap_close(int fd, char *dev);
int tap_write(int fd, char *buf, int len);
int tap_read(int fd, char *buf, int len);

int pty_open(char *dev);
int pty_write(int fd, char *buf, int len);
int pty_read(int fd, char *buf, int len);

int pipe_open(int *fd);
int pipe_write(int fd, char *buf, int len);
int pipe_read(int fd, char *buf, int len);

int tcp_write(int fd, char *buf, int len);
int tcp_read(int fd, char *buf);

int udp_write(int fd, char *buf, int len);
int udp_read(int fd, char *buf);

#endif
