#ifndef BUILDPACKET_H
#define BUILDPACKET_H

#include <libnet.h>
#include <stdlib.h>
#include "portscan.h"

void build_packet( char type );

void * thread_build_syn( void * arg );

void * thread_build_fin( void * arg );

#endif
