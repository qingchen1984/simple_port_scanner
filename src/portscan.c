#include "portscan.h"

void port_scan( char type )
{
    int err;            /* for thread error process */
    pthread_t cp_tid;   /* thread id to call capture_packet */
    pthread_t bp_tid;   /* thread id to call build_packet */
    void * tret;
    memset(port_set, '1', 65535); /* initialize the port set */

    err = pthread_create( &cp_tid, NULL, thread_capture_packet, NULL);
    check_error( err, "capture packet" );
    //err = pthread_join( cp_tid, &tret );
    //sleep(10);

	if( type == 's' ){
		err = pthread_create( &bp_tid, NULL, thread_build_syn, NULL );
		check_error( err, "build syn" );
	}
	else{
		err = pthread_create( &bp_tid, NULL, thread_build_fin, NULL );
        check_error( err, "build fin" );
	}

    err = pthread_join( bp_tid, &tret );
    check_error( err, "thread join");

    sleep(5);

    err = pthread_cancel( cp_tid );
    check_error( err, "thread cancel");

    printf("now need to further process...\n");
}

void check_error( int err, char * msg )
{
    if(err != 0)
        fprintf( stderr, "Thread error: %s, %s\n",
                 msg, strerror( err ) );
}
