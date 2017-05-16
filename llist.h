
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
 * $Id: llist.h,v 1.3.2.2 2008/01/07 22:35:48 mtbishop Exp $
 */ 

#ifndef _VTUN_LLIST_H
#define _VTUN_LLIST_H

struct llist_element {
	struct llist_element * next;
	void * data;
};
typedef struct llist_element llist_elm;

typedef struct {
	llist_elm * head;
	llist_elm * tail;
} llist;


void llist_init(llist *l);
int  llist_add(llist *l, void *d);
int  llist_empty(llist *l);
void * llist_trav(llist *l, int (*f)(void *d, void *u), void *u);
int llist_copy(llist *l, llist *t, void* (*f)(void *d, void *u), void *u);
void * llist_free(llist *l, int (*f)(void *d, void *u), void *u);


#endif /* _VTUN_LLIST_H */
