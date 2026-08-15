#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define MAX_TRACKERS 128
#define MAX_TRACKED_PORTS 128

#define PORT_SCAN_THRESHOLD 10
#define PORT_SCAN_WINDOW_SECONDS 5

typedef struct {
    bool in_use;
    bool alert_generated;

    char source_ip[INET_ADDRSTRLEN];
    char destination_ip[INET_ADDRSTRLEN];

    uint16_t destination_ports[MAX_TRACKED_PORTS];
    size_t port_count;

    time_t window_start;
} ScanTracker;

static ScanTracker scan_trackers[MAX_TRACKERS];

static ScanTracker *get_scan_tracker(const char *source_ip, const char *destination_ip, time_t timestamp) {
    for (size_t i = 0; i <MAX_TRACKERS; i++) {
        if (!scan_trackers[i].in_use) {
            scan_trackers[i].in_use = true;
            scan_trackers[i].alert_generated = false;
            scan_trackers[i].port_count = 0;
            scan_trackers[i].window_start = timestamp;

            snprintf(scan_trackers[i].source_ip, sizeof(scan_trackers[i].source_ip), "%s", source_ip);
            snprintf(scan_trackers[i].destination_ip, sizeof(scan_trackers[i].destination_ip), "%s", destination_ip);

            return &scan_trackers[i];
        }

        if (strcmp(scan_trackers[i].source_ip, source_ip) == 0 && 
                strcmp(scan_trackers[i].destination_ip, destination_ip) == 0) {
            return &scan_trackers[i];
        }
    }

    return NULL;
}

static bool tracker_contains_port(const ScanTracker *tracker, uint16_t destination_port) {
    for (size_t i = 0; i <tracker->port_count; i++) {
        if (tracker->destination_ports[i] == destination_port) {
            return true;
        }
    }

    return false;
}

static void inspect_syn_packet(const char *source_ip, const char *destination_ip, uint16_t destination_port, time_t timestamp) {
    ScanTracker *tracker = get_scan_tracker(source_ip, destination_ip, timestamp);

    if (tracker == NULL) {
        return;
    }

    double elapsed = difftime(timestamp, tracker->window_start);

    if (elapsed > PORT_SCAN_WINDOW_SECONDS) {
        tracker->port_count = 0;
        tracker->alert_generated = false;
        tracker->window_start = timestamp;
    }

    if (!tracker_contains_port(tracker, destination_port) && tracker->port_count < MAX_TRACKED_PORTS) {
        tracker->destination_ports[tracker->port_count] = destination_port;
        tracker->port_count++;
    }

    if (tracker->port_count >= PORT_SCAN_THRESHOLD && !tracker->alert_generated) {
        printf("\n");
        printf("========================================\n");
        printf("ALERT: Possible TCP SYN port scan\n");
        printf("Source IP:      %s\n", tracker->source_ip);
        printf("Destination IP: %s\n", tracker->destination_ip);
        printf("Unique ports:   %zu\n", tracker->port_count);
        printf("Ports:");

        for (size_t i = 0; i < tracker->port_count; i++) {
            printf(" %u", tracker->destination_ports[i]);
        }

        printf("\n");
        printf("========================================\n\n");

        tracker->alert_generated = true;
    }
}

static int link_type;

static void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet) {

    (void) user_data;
    const u_char *ip_start;
    size_t remaining_len;

    if (link_type == DLT_EN10MB) {
        if (packet_header->caplen < sizeof(struct ether_header)) {
            return;
        }

        const struct ether_header *ethernet = (const struct ether_header *) packet;

        if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) {
            return;
        }

        ip_start = packet + sizeof(struct ether_header);
        remaining_len = packet_header->caplen - sizeof(struct ether_header);
    }
    else if (link_type == DLT_NULL) {
        if (packet_header->caplen < sizeof(uint32_t)) {
            return;
        }

        uint32_t family;
        memcpy(&family, packet, sizeof(family));

        if (family != AF_INET) {
            return;
        }

        ip_start = packet + sizeof(uint32_t);
        remaining_len = packet_header->caplen - sizeof(uint32_t);
    }
    else {
        return;
    }

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

            bool syn_set = (tcp_header->th_flags & TH_SYN) != 0;
            bool ack_set = (tcp_header->th_flags & TH_ACK) != 0;

            if (syn_set && !ack_set) {
                inspect_syn_packet(source_ip, destination_ip, ntohs(tcp_header->th_dport), packet_header->ts.tv_sec);
            }

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
    // Use "en0" to capture live network traffic or "lo0" for local testing.
    pcap_t *handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        // Use "en0" to capture live network traffic or "lo0" for local testing.
        fprintf(stderr, "Could not open en0: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    link_type = pcap_datalink(handle);
    if (link_type != DLT_EN10MB && link_type != DLT_NULL) {
        fprintf(stderr, "Unsupported data link type: %d\n", link_type);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    // Use "en0" to capture live network traffic or "lo0" for local testing.
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
