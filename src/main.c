#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

static void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet) {

    (void) user_data;
    
    /*
     * Ethernet packets begin with an Ethernet header.
     * Make sure the captured packet is large enough to contain one.
     */
    if (packet_header->caplen < sizeof(struct ether_header)) {
        fprintf(stderr, "Packet too small for an Ethernet header\n");
        return;
    }

    const struct ether_header *ethernet = (const struct ether_header *) packet;

    /*
     * ether_type tells us what protocol comes after the Ethernet header.
     * ETHERTYPE_IP is IPv4.
     */
    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) {
        return;
    }

    const u_char *ip_start = packet + sizeof(struct ether_header);
    size_t remaining_len = packet_header->caplen - sizeof(struct ether_header);

    if (remaining_len < sizeof(struct ip)) {
        fprintf(stderr, "Packet too small for an IPv4 header\n");
        return;
    }

    const struct ip *ip_header = (const struct ip *) ip_start;

    /*
     * ip_hl is measured in 32-bit words, so multiply by 4 to get bytes.
     */
    size_t ip_header_len = (size_t) ip_header->ip_hl * 4;

    if (ip_header_len < sizeof(struct ip) || remaining_len < ip_header_len) {
        fprintf(stderr, "Invalid IPv4 header length\n");
        return;
    }

    char source_ip[INET_ADDRSTRLEN];
    char destination_ip[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &ip_header->ip_src, source_ip, sizeof(source_ip)) == NULL || 
            inet_ntop(AF_INET, &ip_header->ip_dst, destination_ip, sizeof(destination_ip)) == NULL) {
        perror("inet_ntop");
        return;
    }

    const u_char *transport_start = ip_start + ip_header_len;
    size_t transport_len = remaining_len - ip_header_len;

    switch (ip_header->ip_p) {
        case IPPROTO_TCP: {
            if (transport_len < sizeof(struct tcphdr)) {
                fprintf(stderr, "Packet too small for a TCP header\n");
                return;
            }

            const struct tcphdr *tcp_header = (const struct tcphdr *) transport_start;
            printf("TCP  %s:%u -> %s:%u\n", source_ip, ntohs(tcp_header->th_sport), destination_ip, ntohs(tcp_header->th_dport));

            break;
        }

        case IPPROTO_UDP: {
            if (transport_len < sizeof(struct udphdr)) {
                fprintf(stderr, "Packet too small for a UDP header\n");
                return;
            }

            const struct udphdr *udp_header = (const struct udphdr *) transport_start;
            printf("UDP  %s:%u -> %s:%u\n", source_ip, ntohs(udp_header->uh_sport), destination_ip, ntohs(udp_header->uh_dport));

            break;
        }

        case IPPROTO_ICMP: {
            if (transport_len < sizeof(struct icmp)) {
                fprintf(stderr, "Packet too small for a ICMP header\n");
                return;
            }

            const struct icmp *icmp_header = (const struct icmp *) transport_start;
            printf("ICMP %s -> %s type=%u code=%u\n", source_ip, destination_ip, icmp_header->icmp_type, icmp_header->icmp_code);

            break;
        }

        default:
            printf("IPv4 %s -> %s protocol=%u\n", source_ip, destination_ip, ip_header->ip_p);
            break;
    }
}

int main(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open en0: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    /*
     * This parser expects Ethernet frames.
     */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "The selected interface does not use Ethernet-style packets\n");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    printf("\nListening on en0. Press Ctrl+C to stop.\n");

    // Change to -1 to run until stopped by user
    int result = pcap_loop(handle, -1, packet_handler, NULL);

    if (result == PCAP_ERROR) {
        fprintf(stderr, "Packet capture error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    pcap_close(handle);

    return EXIT_SUCCESS;
}
