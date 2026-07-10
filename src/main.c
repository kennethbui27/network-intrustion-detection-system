#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

static void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet) {

    (void) user_data;
    (void) packet;

    printf("Captured packet: %u bytes captured, %u bytes on wire\n", packet_header->caplen, packet_header->len);
}

int main(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces = NULL;
    pcap_if_t *current = NULL;

    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Could not find network interfaces: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    printf("Available network interfaces:\n");

    for (current = interfaces; current != NULL; current = current->next) {
        printf("  %s", current->name);

        if (current->description != NULL) {
            printf(" - %s", current->description);
        }

        printf("\n");
    }

    pcap_freealldevs(interfaces);
    pcap_t *handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open interface en0: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    printf("\nListening on en0. Press Ctrl+C to stop.\n");

    int result = pcap_loop(handle, 10, packet_handler, NULL);

    if (result == PCAP_ERROR) {
        fprintf(stderr, "Packet capture error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    pcap_close(handle);

    return EXIT_SUCCESS;
}
