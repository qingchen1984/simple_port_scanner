#include "captpacket.h"

void tcp_protocol_packet_callback(
	u_char *argument, const struct pcap_pkthdr* packet_header,
	const u_char * packet_content )
{
	/* IP part */
	struct sniff_ip *ip_protocol;
	u_int ip_header_length;
	u_int offset;
	u_char tos;    //service quality
	u_int16_t checksum;
	/* get IP protocol payload, skip the ethernet header*/
	ip_protocol = ( struct sniff_ip * )( packet_content + 14 );
	checksum = ntohs( ip_protocol->ip_sum ); //get the checksum
	ip_header_length = ip_protocol->ip_vhl >> 2;     //get header length
	tos = ip_protocol->ip_tos;               //get service quality
	offset = ntohs( ip_protocol->ip_off );   //fragment offset


	/* TCP part */
	struct sniff_tcp *tcp_protocol;
	struct servent *service;
	u_char flags;
	int tcp_header_length;
	u_short source_port;
	u_short destination_port;
	u_short windows;
	u_short urgent_pointer;
	u_int sequence;
	u_int acknowledgement;

	/*get tcp protocol content, skip ethernet and IP header*/
	tcp_protocol = ( struct sniff_tcp * )( packet_content+14+20 );
	source_port = ntohs( tcp_protocol->th_sport );
	destination_port = ntohs( tcp_protocol->th_dport );
	tcp_header_length = tcp_protocol->th_offx2 * 4;
	sequence = ntohl( tcp_protocol->th_ack );
	windows = ntohs( tcp_protocol->th_win );
	urgent_pointer = ntohs( tcp_protocol->th_urp );

	flags = tcp_protocol->th_flags;
	checksum = ntohs( tcp_protocol->th_sum );

	port_set[source_port] = '0';      //get msg means port not open.
}

void capture_packet(  )
{
	pcap_t* pcap_handle;
	char error_content[PCAP_ERRBUF_SIZE];
	char *net_interface;
	struct bpf_program bpf_filter;
	/* "" indicates capture all packet*/
	char bpf_filter_string[64];
	bpf_u_int32 net_mask;
	bpf_u_int32 net_ip;

	/* get network interface */
	net_interface = pcap_lookupdev( error_content );
	if(net_interface == NULL){
		fprintf(stderr, "Couldn't find default device: %s\n",
           error_content);
		exit(1);
	}
	printf("Device: %s\n", net_interface);

	/* get network addr, mask */
	if( pcap_lookupnet( net_interface, &net_ip,
                     &net_mask, error_content ) == -1){
		fprintf(stderr, "Couldn't get netmask for device %s\n",
            net_interface);
		exit(1);
	}

	/* open network interface */
	pcap_handle = pcap_open_live( net_interface, BUFSIZ,
                               1, 0, error_content );
	if(pcap_handle == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n",
           net_interface, error_content);
		exit(1);
	}

	sprintf(bpf_filter_string, "host %s and tcp", dst_ip_str);      /* filter rules */
	/* compile the filter */
	if( pcap_compile( pcap_handle, &bpf_filter,
                   bpf_filter_string, 0, net_ip ) == -1){
		fprintf(stderr, "couldn't parse filter: %s: %s\n",
           bpf_filter_string, pcap_geterr(pcap_handle));
		exit(1);
	}
	/* set the filter */
	if( pcap_setfilter( pcap_handle, &bpf_filter ) == -1 ){
		fprintf(stderr, "couldn't install filter: %s: %s\n",
          bpf_filter_string, pcap_geterr(pcap_handle));
		exit(1);
	}

	/* register the call back function, capture the packet in loop
	   then, callback function analysis the packet */
	pcap_loop( pcap_handle, -1, tcp_protocol_packet_callback, NULL );

	pcap_close( pcap_handle );

}

void * thread_capture_packet( void * arg )
{
    printf("now in thread of capturing packet\n");
    capture_packet( );
    printf("now thread of capturing packet done\n");
    return ( (void *)1 );
}
