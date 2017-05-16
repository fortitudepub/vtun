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
 * $Id: auth.c,v 1.9.2.4 2009/04/24 09:15:33 mtbishop Exp $
 */ 

/*
 * Challenge based authentication. 
 * Thanx to Chris Todd<christ@insynq.com> for the good idea.
 */ 

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>

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

/* Encryption and Decryption of the challenge key */
#ifdef HAVE_SSL

#include <openssl/md5.h>
#include <openssl/blowfish.h>
#include <openssl/rand.h>

void gen_chal(char *buf)
{
   RAND_bytes(buf, VTUN_CHAL_SIZE);
}

void encrypt_chal(char *chal, char *pwd)
{ 
   register int i;
   BF_KEY key;

   BF_set_key(&key, 16, MD5(pwd,strlen(pwd),NULL));

   for(i=0; i < VTUN_CHAL_SIZE; i += 8 )
      BF_ecb_encrypt(chal + i,  chal + i, &key, BF_ENCRYPT);
}

void decrypt_chal(char *chal, char *pwd)
{ 
   register int i;
   BF_KEY key;

   BF_set_key(&key, 16, MD5(pwd,strlen(pwd),NULL));

   for(i=0; i < VTUN_CHAL_SIZE; i += 8 )
      BF_ecb_encrypt(chal + i,  chal + i, &key, BF_DECRYPT);
}

#else /* HAVE_SSL */

void encrypt_chal(char *chal, char *pwd)
{ 
   char * xor_msk = pwd;
   register int i, xor_len = strlen(xor_msk);

   for(i=0; i < VTUN_CHAL_SIZE; i++)
      chal[i] ^= xor_msk[i%xor_len];
}

void inline decrypt_chal(char *chal, char *pwd)
{ 
   encrypt_chal(chal, pwd);
}

/* Generate PSEUDO random challenge key. */
void gen_chal(char *buf)
{
   register int i;
 
   srand(time(NULL));

   for(i=0; i < VTUN_CHAL_SIZE; i++)
      buf[i] = (unsigned int)(255.0 * rand()/RAND_MAX);
}
#endif /* HAVE_SSL */

/* 
 * Functions to convert binary flags to character string.
 * string format:  <CS64> 
 * C - compression, S - speed for shaper and so on.
 */ 

char *bf2cf(struct vtun_host *host)
{
     static char str[20], *ptr = str;

     *(ptr++) = '<';

     switch( host->flags & VTUN_PROT_MASK ){
	case VTUN_TCP:
	   *(ptr++) = 'T';
	   break;

	case VTUN_UDP:
	   *(ptr++) = 'U';
	   break;
     }

     switch( host->flags & VTUN_TYPE_MASK ){
	case VTUN_TTY:
	   *(ptr++) = 't'; 	
	   break;

	case VTUN_PIPE:
	   *(ptr++) = 'p';
	   break; 	

	case VTUN_ETHER:
	   *(ptr++) = 'e';
	   break;

	case VTUN_TUN:
	   *(ptr++) = 'u';
	   break;
     } 

     if( (host->flags & VTUN_SHAPE) /* && host->spd_in */)
	ptr += sprintf(ptr,"S%d",host->spd_in);

     if( host->flags & VTUN_ZLIB )
	ptr += sprintf(ptr,"C%d", host->zlevel);

     if( host->flags & VTUN_LZO )
	ptr += sprintf(ptr,"L%d", host->zlevel);

     if( host->flags & VTUN_KEEP_ALIVE )
	*(ptr++) = 'K';

     if( host->flags & VTUN_ENCRYPT ) {
        if (host->cipher == VTUN_LEGACY_ENCRYPT) { /* use old flag method */
	   ptr += sprintf(ptr,"E");
	} else {
	   ptr += sprintf(ptr,"E%d", host->cipher);
	}
     }

     strcat(ptr,">");

     return str;
}

/* return 1 on success, otherwise 0 
   Example:
   FLAGS: <TuE1>
*/

int cf2bf(char *str, struct vtun_host *host)
{
     char *ptr, *p;
     int s;

     if( (ptr = strchr(str,'<')) ){ 
	vtun_syslog(LOG_DEBUG,"Remote Server sends %s.", ptr);
	ptr++;
	while(*ptr){  
	   switch(*ptr++){
	     case 't':
		host->flags |= VTUN_TTY;
		break;
	     case 'p':
		host->flags |= VTUN_PIPE;
		break;
	     case 'e':
		host->flags |= VTUN_ETHER;
		break;
	     case 'u':
		host->flags |= VTUN_TUN;
		break;
	     case 'U':
		host->flags &= ~VTUN_PROT_MASK;
		host->flags |= VTUN_UDP;
		break;
	     case 'T':
		host->flags &= ~VTUN_PROT_MASK;
		host->flags |= VTUN_TCP;
		break;
	     case 'K':
		host->flags |= VTUN_KEEP_ALIVE;
		break;
	     case 'C':
		if((s = strtol(ptr,&p,10)) == ERANGE || ptr == p) 
		   return 0;
		host->flags |= VTUN_ZLIB;
		host->zlevel = s; 
		ptr = p;
		break;
	     case 'L':
		if((s = strtol(ptr,&p,10)) == ERANGE || ptr == p) 
		   return 0;
		host->flags |= VTUN_LZO;
		host->zlevel = s; 
		ptr = p;
		break;
	     case 'E':
	        /* new form is 'E10', old form is 'E', so remove the
		   ptr==p check */
		if((s = strtol(ptr,&p,10)) == ERANGE) {
		   vtun_syslog(LOG_ERR,"Garbled encryption method.  Bailing out.");
		   return 0;
		}
		host->flags |= VTUN_ENCRYPT;
		if (0 == s) {
		   host->cipher = VTUN_LEGACY_ENCRYPT;
		   vtun_syslog(LOG_INFO,"Remote server using older encryption.");
		} else {
		   host->cipher = s; 
		}
		ptr = p;
		break;
     	     case 'S':
		if((s = strtol(ptr,&p,10)) == ERANGE || ptr == p) 
		   return 0;
		if( s ){
	    	   host->flags |= VTUN_SHAPE;
		   host->spd_out = s; 
		}
		ptr = p;
		break;
	     case 'F':
	        /* reserved for Feature transmit */
	       break;
	     case '>':
	        return 1;
	     default:
		return 0;
	   }
	}
     }
     return 0;
}

/* 
 * Functions to convert binary key data to character string.
 * string format:  <char_data> 
 */ 

char *cl2cs(char *chal)
{
     static char str[VTUN_CHAL_SIZE*2+3], *chr="abcdefghijklmnop";
     register char *ptr = str;
     register int i;

     *(ptr++) = '<';
     for(i=0; i<VTUN_CHAL_SIZE; i++){
	*(ptr++) = chr[ ((chal[i] & 0xf0) >> 4) ];  
	*(ptr++) = chr[ (chal[i] & 0x0f) ];
     }  

     *(ptr++) = '>';
     *ptr = '\0';

     return str;
}

int cs2cl(char *str, char *chal)
{
     register char *ptr = str;
     register int i;

     if( !(ptr = strchr(str,'<')) ) 
        return 0;
     ptr++;
     if( !strtok(ptr,">") || strlen(ptr) != VTUN_CHAL_SIZE*2 )
        return 0;

     for(i=0; i<VTUN_CHAL_SIZE && *ptr; i++, ptr+=2) {
	chal[i]  = (*ptr - 'a') << 4;  
	chal[i] |= *(ptr+1) - 'a';
     }

     return 1;
}   

/* Authentication (Server side) */
struct vtun_host * auth_server(int fd)
{
        char chal_req[VTUN_CHAL_SIZE], chal_res[VTUN_CHAL_SIZE];	
	char buf[VTUN_MESG_SIZE], *str1, *str2;
        struct vtun_host *h = NULL;
	char *host = NULL;
	int  stage;

        set_title("authentication");

	print_p(fd,"VTUN server ver %s\n",VTUN_VER);

	stage = ST_HOST;

	while( readn_t(fd, buf, VTUN_MESG_SIZE, vtun.timeout) > 0 ){
	   buf[sizeof(buf)-1]='\0';
	   strtok(buf,"\r\n");

	   if( !(str1=strtok(buf," :")) )
	      break;
	   if( !(str2=strtok(NULL," :")) )
	      break;

	   switch( stage ){
	     case ST_HOST:
	        if( !strcmp(str1,"HOST") ){
		   host = strdup(str2);

		   gen_chal(chal_req);
		   print_p(fd,"OK CHAL: %s\n", cl2cs(chal_req));

		   stage = ST_CHAL;
		   continue;
	        }
		break;
	     case ST_CHAL:
	        if( !strcmp(str1,"CHAL") ){
		   if( !cs2cl(str2,chal_res) )
		      break; 
		   
		   if( !(h = find_host(host)) )
		      break;

		   decrypt_chal(chal_res, h->passwd);   		
	
		   if( !memcmp(chal_req, chal_res, VTUN_CHAL_SIZE) ){
		      /* Auth successeful. */

		      /* Lock host */	
		      if( lock_host(h) < 0 ){
		         /* Multiple connections are denied */
		         h = NULL;
		         break;
		      }	
		      print_p(fd,"OK FLAGS: %s\n", bf2cf(h)); 
 		   } else
		      h = NULL;
	        }
		break;
 	   }
	   break;
	}

	if( host )
	   free(host);

	if( !h )
	   print_p(fd,"ERR\n");	

	return h;
}

/* Authentication (Client side) */
int auth_client(int fd, struct vtun_host *host)
{
	char buf[VTUN_MESG_SIZE], chal[VTUN_CHAL_SIZE];
	int stage, success=0 ;
	
	stage = ST_INIT;

	while( readn_t(fd, buf, VTUN_MESG_SIZE, vtun.timeout) > 0 ){
	   buf[sizeof(buf)-1]='\0';
	   switch( stage ){
		case ST_INIT:
	    	   if( !strncmp(buf,"VTUN",4) ){
		      stage = ST_HOST;
		      print_p(fd,"HOST: %s\n",host->host);
		      continue;
	           }
		   break;	

	        case ST_HOST:
		   if( !strncmp(buf,"OK",2) && cs2cl(buf,chal)){
		      stage = ST_CHAL;
					
		      encrypt_chal(chal,host->passwd);
		      print_p(fd,"CHAL: %s\n", cl2cs(chal));

		      continue;
	   	   }
		   break;	
	
	        case ST_CHAL:
		   if( !strncmp(buf,"OK",2) && cf2bf(buf,host) )
		      success = 1;
		   break;
	   }
	   break;
	}

	return success;
}
