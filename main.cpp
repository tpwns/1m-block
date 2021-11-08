#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <iostream>


#include "db.h"
#include <libnetfilter_queue/libnetfilter_queue.h>

struct my_ipv4_hdr
{
    u_int8_t  ip_v_hl;       /* version, header length */
    u_int8_t  ip_tos;       /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t  ip_ttl;          /* time to live */
    u_int8_t  ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct my_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t  th_off;        /* data offset */    
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

std::string http_method[9] = {"GET","POST","HEAD","OPTIONS","PUT","DELETE","TRACE","CONNECT"};
std::string dbname;			//sqliet3 db name

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	int id = 0;
	int ret;
	unsigned char *pkt;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	int i;
	
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	}
	ret = nfq_get_payload(nfa, &pkt);   


	bool is_http=false;

	struct my_ipv4_hdr *ip_hdr = (struct my_ipv4_hdr *)(pkt);
	struct my_tcp_hdr *tcp_hdr = (struct my_tcp_hdr *)(ip_hdr+1);
	uint16_t tcp_hdr_len = (tcp_hdr->th_off>>4) << 2;	//upper 4bit * 4
	const char *http_hdr = (const char *)(tcp_hdr);
	http_hdr = http_hdr += tcp_hdr_len;
	
	if(ntohs(tcp_hdr->th_dport) == 80 || ntohs(tcp_hdr->th_sport) == 80)	//1. 80번 포트인지 체크
	{	
	
	//2. http method가 존재하는지 확인
		for(i=0;i<8;i++){
			if(!strncmp(http_hdr,http_method[i].c_str(),http_method[i].length())){
				is_http=true;
				break;
			}
		}
	}

	/*http가 아닌 경우*/
	if(!is_http){
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	/*http인 경우*/
	while(memcmp(http_hdr,"Host:",5)){
		http_hdr++;
	}
	http_hdr+=5;
	if(*http_hdr==' '){
		http_hdr++;
	}
	std::string host;
	while(*http_hdr!='\r'){
		host += *http_hdr;
		http_hdr++;
	}

	//db에 host가 존재하는지 쿼리
	if(db_query_host(host,dbname)){
		std::cout << "[DROP] [" << http_method[i] << "] " << host <<"\n";
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);	//db에 host가 존재하면 drop
	}
	else{
		std::cout << "[ACCEPT] [" << http_method[i] << "] " << host <<"\n";
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);	//존재하지 않으면 accept
	}
	
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	if(argc != 2) {
		printf("syntax : 1m-block <site list file>\n");
		printf("sample : 1m-block top-1m.db\n");
		return -1;
	}

	dbname = argv[1];
	if(dbname.substr(dbname.length()-3) != ".db"){
		printf("Site list file must be sqlite3 .db file format.\n");
		return -1;
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);    //nfq에 cb라는 함수를 등록, 패킷이 넷필터에 들어올때 cb(call back)이 실행
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
