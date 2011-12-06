#ifndef SCANNER_H
#define SCANNER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>
#include "buildpacket.h"
#include "captpacket.h"

/* GLOBOL VARIBLE */
char * dst_ip_str;          /* point to distination addr */
char port_set[65535];       /* for bit manipulation */

void port_scan( char type );

void check_error( int err, char * msg );
#endif
