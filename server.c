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
 * $Id: server.c,v 1.9.2.3 2012/07/09 01:01:08 mtbishop Exp $
 */ 

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/socket.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "lock.h"
#include "auth.h"

#include "compat.h"
#include "netlib.h"

static volatile sig_atomic_t server_term;
static void sig_term(int sig)
{
     vtun_syslog(LOG_INFO,"Terminated");
     server_term = VTUN_SIG_TERM;
}

void connection(int sock)
{
     struct sockaddr_in my_addr, cl_addr;
     struct vtun_host *host;
     struct sigaction sa;
     char *ip;
     int opt;

     opt = sizeof(struct sockaddr_in);
     if( getpeername(sock, (struct sockaddr *) &cl_addr, &opt) ){
        vtun_syslog(LOG_ERR, "Can't get peer name");
        exit(1);
     }
     opt = sizeof(struct sockaddr_in);
     if( getsockname(sock, (struct sockaddr *) &my_addr, &opt) < 0 ){
        vtun_syslog(LOG_ERR, "Can't get local socket address");
        exit(1); 
     }

     ip = strdup(inet_ntoa(cl_addr.sin_addr));

     io_init();

     if( (host=auth_server(sock)) ){	
        sa.sa_handler=SIG_IGN;
	sa.sa_flags=SA_NOCLDWAIT;;
        sigaction(SIGHUP,&sa,NULL);

	vtun_syslog(LOG_INFO,"Session %s[%s:%d] opened", host->host, ip, 
					ntohs(cl_addr.sin_port) );
        host->rmt_fd = sock; 
	
        host->sopt.laddr = strdup(inet_ntoa(my_addr.sin_addr));
        host->sopt.lport = vtun.bind_addr.port;
        host->sopt.raddr = strdup(ip);
	host->sopt.rport = ntohs(cl_addr.sin_port);

	/* Start tunnel */
	tunnel(host);

	vtun_syslog(LOG_INFO,"Session %s closed", host->host);

	/* Unlock host. (locked in auth_server) */	
	unlock_host(host);
     } else {
        vtun_syslog(LOG_INFO,"Denied connection from %s:%d", ip,
					ntohs(cl_addr.sin_port) );
     }
     close(sock);

     exit(0);
}

void listener(void)
{
     struct sigaction sa;
     struct sockaddr_in my_addr, cl_addr;
     int s, s1, opt;

     memset(&my_addr, 0, sizeof(my_addr));
     my_addr.sin_family = AF_INET;

     /* Set listen address */
     if( generic_addr(&my_addr, &vtun.bind_addr) < 0)
     {
        vtun_syslog(LOG_ERR, "Can't fill in listen socket");
        exit(1);
     }

     if( (s=socket(AF_INET,SOCK_STREAM,0))== -1 ){
	vtun_syslog(LOG_ERR,"Can't create socket");
	exit(1);
     }

     opt=1;
     setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); 

     if( bind(s,(struct sockaddr *)&my_addr,sizeof(my_addr)) ){
	vtun_syslog(LOG_ERR,"Can't bind to the socket");
	exit(1);
     }

     if( listen(s, 10) ){
	vtun_syslog(LOG_ERR,"Can't listen on the socket");
	exit(1);
     }

     memset(&sa,0,sizeof(sa));
     sa.sa_flags = SA_NOCLDWAIT;
     sa.sa_handler=sig_term;
     sigaction(SIGTERM,&sa,NULL);
     sigaction(SIGINT,&sa,NULL);
     server_term = 0;

     set_title("waiting for connections on port %d", vtun.bind_addr.port);

     while( (!server_term) || (server_term == VTUN_SIG_HUP) ){
        opt=sizeof(cl_addr);
	if( (s1=accept(s,(struct sockaddr *)&cl_addr,&opt)) < 0 )
	   continue; 

	switch( fork() ){
	   case 0:
	      close(s);
	      connection(s1);
	      break;
	   case -1:
	      vtun_syslog(LOG_ERR, "Couldn't fork()");
	   default:
	      close(s1);
	      break;
	}
     }  
}	

void server(int sock)
{
     struct sigaction sa;

     sa.sa_handler=SIG_IGN;
     sa.sa_flags=SA_NOCLDWAIT;;
     sigaction(SIGINT,&sa,NULL);
     sigaction(SIGQUIT,&sa,NULL);
     sigaction(SIGCHLD,&sa,NULL);
     sigaction(SIGPIPE,&sa,NULL);
     sigaction(SIGUSR1,&sa,NULL);

     vtun_syslog(LOG_INFO,"VTUN server ver %s (%s)", VTUN_VER,
		 vtun.svr_type == VTUN_INETD ? "inetd" : "stand" );

     switch( vtun.svr_type ){
	case VTUN_STAND_ALONE:
	   listener();
	   break;
        case VTUN_INETD:
	   connection(sock);
	   break;
     }    
}
