#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define host_port 80
#define dst_port 445

#define dst_ip "192.168.0.5"
#define src_ip "192.168.0.3"

#define dst_mac "\x10\xda\x43\xdf\x31\xdc"
#define src_mac "\x7c\xc2\xc6\x31\x02\xf1"

typedef struct ip_hdr
{
    unsigned char ip_header_len:4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
    unsigned char ip_version :4; // 4-bit IPv4 version
    unsigned char ip_tos; // IP type of service
    unsigned short ip_total_length; // Total length
    unsigned short ip_id; // Unique identifier

    unsigned char ip_frag_offset :5; // Fragment offset field

    unsigned char ip_more_fragment :1;
    unsigned char ip_dont_fragment :1;
    unsigned char ip_reserved_zero :1;

    unsigned char ip_frag_offset1; //fragment offset

    unsigned char ip_ttl; // Time to live
    unsigned char ip_protocol; // Protocol(TCP,UDP etc)
    unsigned short ip_checksum; // IP checksum
    unsigned int ip_srcaddr; // Source address
    unsigned int ip_destaddr; // Source address
} IPV4_HDR, *PIPV4_HDR, *LPIPV4_HDR;

// TCP header
typedef struct tcp_header
{
    unsigned short source_port; // source port
    unsigned short dest_port; // destination port
    unsigned int sequence; // sequence number - 32 bits
    unsigned int acknowledge; // acknowledgement number - 32 bits

    unsigned char ns :1; //Nonce Sum Flag Added in RFC 3540.
    unsigned char reserved_part1:3; //according to rfc
    unsigned char data_offset:4; /*The number of 32-bit words in the TCP header.
This indicates where the data begins.
The length of the TCP header is always a multiple
of 32 bits.*/

    unsigned char fin :1; //Finish Flag
    unsigned char syn :1; //Synchronise Flag
    unsigned char rst :1; //Reset Flag
    unsigned char psh :1; //Push Flag
    unsigned char ack :1; //Acknowledgement Flag
    unsigned char urg :1; //Urgent Flag

    unsigned char ecn :1; //ECN-Echo Flag
    unsigned char cwr :1; //Congestion Window Reduced Flag

////////////////////////////////

    unsigned short window; // window
    unsigned short checksum; // checksum
    unsigned short urgent_pointer; // urgent pointer
} TCP_HDR , *PTCP_HDR , *LPTCP_HDR , TCPHeader , TCP_HEADER;

struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcp_header tcp;
};

unsigned short TcpCheckSum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;
    while(size >1)
    {
        cksum+=*buffer++;
        size -=sizeof(unsigned short);
    }
    if(size)
        cksum += *(unsigned char*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);
}

unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

char* create_packet() {
    char* buf = malloc(1000); //buf is the complete packet
    memcpy(buf, dst_mac, 7);
    strcat(buf, src_mac);
    strcat(buf, "\x08\x00");
    buf += 14;

    IPV4_HDR *v4hdr=NULL;
    TCP_HDR *tcphdr=NULL;

    struct sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(host_port);
    inet_pton(AF_INET, src_ip, &bind_addr.sin_addr.s_addr);

    v4hdr = (IPV4_HDR *)buf; //let's point to the ip header portion
    v4hdr->ip_version=4;
    v4hdr->ip_header_len=5;
    v4hdr->ip_tos = 0;
    v4hdr->ip_total_length = htons(sizeof(IPV4_HDR) + sizeof(TCP_HDR));
    v4hdr->ip_id = htons(2);
    v4hdr->ip_frag_offset = 0;
    v4hdr->ip_frag_offset1 = 0;
    v4hdr->ip_reserved_zero = 0;
    v4hdr->ip_dont_fragment = 1;
    v4hdr->ip_more_fragment = 0;
    v4hdr->ip_ttl = 100;
    v4hdr->ip_protocol = IPPROTO_TCP;
    v4hdr->ip_srcaddr = inet_addr(src_ip);
    v4hdr->ip_destaddr = inet_addr(dst_ip);
    v4hdr->ip_checksum = csum((unsigned short*)v4hdr, sizeof(IPV4_HDR));


    tcphdr = (TCP_HDR *)&buf[sizeof(IPV4_HDR)]; //get the pointer to the tcp header in the packet

    tcphdr->source_port = htons(host_port);
    tcphdr->dest_port = htons(dst_port);

    tcphdr->sequence = 0xABCDEFAB;

    tcphdr->data_offset = 5;

    tcphdr->cwr=0;
    tcphdr->ecn=0;
    tcphdr->urg=0;
    tcphdr->ack=0;
    tcphdr->psh=0;
    tcphdr->rst=0;
    tcphdr->syn=1;
    tcphdr->fin=0;
    tcphdr->ns=0;


    struct pseudo_header pseudo_tcp_header;
    pseudo_tcp_header.source_address = inet_addr(src_ip);
    pseudo_tcp_header.dest_address = inet_addr(dst_ip);
    pseudo_tcp_header.placeholder = 0;
    pseudo_tcp_header.protocol = IPPROTO_TCP;
    pseudo_tcp_header.tcp_length = htons(sizeof(TCP_HDR));
    memcpy(&pseudo_tcp_header.tcp, tcphdr, sizeof(TCP_HDR));

    tcphdr->checksum = 0;
    tcphdr->checksum = TcpCheckSum((unsigned short*)&pseudo_tcp_header, sizeof(struct pseudo_header));

    buf -= 14;
    return buf;
}
