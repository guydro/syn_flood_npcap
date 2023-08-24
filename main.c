#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#include "create_packet.c"

/* case-insensitive string comparison that may mix up special characters and numbers */
int close_enough(char *one, char *two)
{
    while (*one && *two)
    {
        if ( *one != *two && !(
                (*one >= 'a' && *one - *two == 0x20) ||
                (*two >= 'a' && *two - *one == 0x20)
        ))
        {
            return 0;
        }
        one++;
        two++;
    }
    if (*one || *two)
    {
        return 0;
    }
    return 1;
}

#define ORIG_PACKET_LEN 64
int main(int argc, char **argv)
{
    setbuf(stdout, 0);

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char *packet = create_packet();
    size_t packet_len = ORIG_PACKET_LEN;
    pcap_if_t *ifaces = NULL;
    pcap_if_t *dev = NULL;
    pcap_addr_t *addr = NULL;

    /* Check the validity of the command line */
    if (argc != 2)
    {
        printf("usage: %s interface", argv[0]);
        return 1;
    }

    if (0 != pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf)) {
        fprintf(stderr, "Failed to initialize pcap lib: %s\n", errbuf);
        return 2;
    }

    /* Find the IPv4 address of the device */
    if (0 != pcap_findalldevs(&ifaces, errbuf)) {
        fprintf(stderr, "Failed to get list of devices: %s\n", errbuf);
        return 2;
    }

    for (dev = ifaces; dev != NULL; dev = dev->next)
    {
        if (close_enough(dev->name, argv[1]))
        {
            break;
        }
    }
    if (dev == NULL) {
        fprintf(stderr, "Could not find %s in the list of devices\n", argv[1]);
        return 3;
    }

    for (addr = dev->addresses; addr != NULL; addr = addr->next)
    {
        if (addr->addr->sa_family == AF_INET)
        {
            break;
        }
    }
    if (addr == NULL) {
        fprintf(stderr, "Could not find IPv4 address for %s\n", argv[1]);
        return 3;
    }

    /* Open the adapter */
    if ((fp = pcap_open_live(argv[1],		// name of the device
                             0, // portion of the packet to capture. 0 == no capture.
                             0, // non-promiscuous mode
                             1000,			// read timeout
                             errbuf			// error buffer
    )) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", argv[1]);
        return 2;
    }


    /* Send down the packet */
    int i=0;
    while(i++<10){
    if (pcap_sendpacket(fp,	// Adapter
                        (u_char*) packet, // buffer with the packet
                        packet_len // size
    ) != 0)
    {
        pcap_perror(fp, "\nError sending the packet");
        return 3;
    }}

    pcap_close(fp);
    return 0;
}
