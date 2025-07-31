//
// Created by Baris Ortanca on 31/07/2025.
//

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    pcap_dumper_t *dumper = (pcap_dumper_t *)args;
    printf("Packet captured: length %d\n", header->len);
    pcap_dump((u_char *)dumper, header, packet);
    pcap_dump_flush(dumper);
}

int start_sniffing(const char *interface_name, const char *output_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netmask, ip;

    if (pcap_lookupnet(interface_name, &ip, &netmask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s: %s\n", interface_name, errbuf);
        netmask = 0; // default mask 255.255.255.0
    }

    pcap_t *handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface_name, errbuf);
        return -1;
    }

    struct bpf_program filter_program;
    char filter_exp[] = "";


    if (pcap_compile(handle, &filter_program, filter_exp, 0, netmask) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    if (pcap_setfilter(handle, &filter_program) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&filter_program);
        pcap_close(handle);
        return -1;
    }


    pcap_dumper_t *dumper = pcap_dump_open(handle, output_file);
    if (dumper == NULL) {
        fprintf(stderr, "Couldn't open dump file %s: %s\n", output_file, pcap_geterr(handle));
        pcap_freecode(&filter_program);
        pcap_close(handle);
        return -1;
    }

    pcap_loop(handle, -1, packet_handler, (u_char *)dumper);

    pcap_dump_close(dumper);
    pcap_freecode(&filter_program);
    pcap_close(handle);

    return 0;
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <interface> <output_file>\n", argv[0]);
        return 1;
    }
    return start_sniffing(argv[1], argv[2]);
}