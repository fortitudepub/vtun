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
 * $Id: lock.c,v 1.6.2.2 2008/01/07 22:35:50 mtbishop Exp $
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <syslog.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h" 
#include "lock.h"

int create_lock(char * file)
{
  char tmp_file[255], str[20];
  int  fd, pid, ret;
   
  pid = getpid();  
  ret = 0;

  /* Create temp file */
  sprintf(tmp_file, "%s_%d_tmp\n", file, pid);
  if( (fd = open(tmp_file, O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0 ){
     vtun_syslog(LOG_ERR, "Can't create temp lock file %s", file);
     return -1;
  }

  pid = sprintf(str, "%d\n", pid);
  if( write(fd, str, pid) == pid ){
     /* Create lock file */
     if( link(tmp_file, file) < 0 ){
        /* Oops, already locked */
        ret = -1;
     }
  } else { 
     vtun_syslog(LOG_ERR, "Can't write to %s", tmp_file);
     ret = -1;
  }
  close(fd);

  /* Remove temp file */
  unlink(tmp_file);

  return ret;
}

pid_t read_lock(char * file)
{
  char str[20];
  int  fd, pid;

  /* Read PID from existing lock */
  if( (fd = open(file, O_RDONLY)) < 0)
     return -1;

  pid = read(fd,str,sizeof(str));
  close(fd);
  if( pid <= 0 )
     return -1;

  str[sizeof(str)-1]='\0';
  pid = strtol(str, NULL, 10);
  if( !pid || errno == ERANGE ){
     /* Broken lock file */
     if( unlink(file) < 0 )
        vtun_syslog(LOG_ERR, "Unable to remove broken lock %s", file);
     return -1;
  }

  /* Check if process is still alive */
  if( kill(pid, 0) < 0 && errno == ESRCH ){
     /* Process is dead. Remove stale lock. */
     if( unlink(file) < 0 )
        vtun_syslog(LOG_ERR, "Unable to remove stale lock %s", file);
     return -1;
  }

  return pid;
}

int lock_host(struct vtun_host * host)
{
  char lock_file[255];
  struct timespec tm;
  int pid, i;

  if( host->multi == VTUN_MULTI_ALLOW )
     return 0;

  sprintf(lock_file, "%s/%s", VTUN_LOCK_DIR, host->host);

  /* Check if lock already exists. */
  if( (pid = read_lock(lock_file)) > 0 ){ 
     /* Old process is alive */
     switch( host->multi ){
	case VTUN_MULTI_KILL:
           vtun_syslog(LOG_INFO, "Killing old connection (process %d)", pid);
           if( kill(pid, SIGTERM) < 0 && errno != ESRCH ){
              vtun_syslog(LOG_ERR, "Can't kill process %d. %s",pid,strerror(errno));
              return -1;
           }
           /* Give it a time(up to 5 secs) to terminate */
	   for(i=0; i < 10 && !kill(pid, 0); i++ ){
              tm.tv_sec = 0; tm.tv_nsec = 500000000; 
              nanosleep(&tm, NULL);
	   }

	   /* Make sure it's dead */		 
           if( !kill(pid, SIGKILL) ){
              vtun_syslog(LOG_ERR, "Process %d ignored TERM, killed with KILL", pid);
   	      /* Remove lock */
              if( unlink(lock_file) < 0 )
                 vtun_syslog(LOG_ERR, "Unable to remove lock %s", lock_file);
	   }

	   break;
        case VTUN_MULTI_DENY:
           return -1;
     }
  }
  return create_lock(lock_file);
}

void unlock_host(struct vtun_host *host)
{ 
  char lock_file[255];

  if( host->multi == VTUN_MULTI_ALLOW )
     return;

  sprintf(lock_file, "%s/%s", VTUN_LOCK_DIR, host->host);

  if( unlink(lock_file) < 0 )
     vtun_syslog(LOG_ERR, "Unable to remove lock %s", lock_file);
}
