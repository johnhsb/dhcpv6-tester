/*
 * ICMPv6 Echo Request Tool with Source IP Support
 * Tool to send ICMPv6 echo requests with custom packet sizes and source IP
 *
 * Compile: gcc -o icmpv6_echo icmpv6_echo.c
 * Usage: sudo ./icmpv6_echo [options] <destination> <packet_size>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>

#define PACKET_SIZE 65535
#define DEFAULT_COUNT 4
#define DEFAULT_TIMEOUT 5

typedef struct {
    char *dest_addr;
    char *src_addr;
    int packet_size;
    int count;
    int timeout;
    int dontfrag;
} test_config_t;

void print_usage(const char *prog_name) {
    printf("ICMPv6 Echo Request Tool with Source IP Support\n");
    printf("================================================\n\n");
    printf("Usage: %s [options] <destination> <packet_size>\n\n", prog_name);
    printf("Required Arguments:\n");
    printf("  destination       Destination IPv6 address\n");
    printf("  packet_size       Total packet size in bytes (8-65535)\n\n");
    printf("Options:\n");
    printf("  -s <source_ip>    Source IPv6 address (optional)\n");
    printf("  -c <count>        Number of packets to send (default: %d)\n", DEFAULT_COUNT);
    printf("  -t <timeout>      Response timeout in seconds (default: %d)\n", DEFAULT_TIMEOUT);
    printf("  -f                Enable Don't Fragment (disable fragmentation)\n");
    printf("  -h                Show this help message\n\n");
    printf("Examples:\n");
    printf("  # Basic test\n");
    printf("  %s 2001:4860:4860::8888 1500\n\n", prog_name);
    printf("  # Specify source IP\n");
    printf("  %s -s 2001:db8::1 2001:4860:4860::8888 3000\n\n", prog_name);
    printf("  # With count and source IP\n");
    printf("  %s -s 2001:db8::1 -c 10 2001:4860:4860::8888 3000\n\n", prog_name);
    printf("  # Link-local with source\n");
    printf("  %s -s fe80::1%%eth0 fe80::2%%eth0 2000\n\n", prog_name);
    printf("  # MTU test with Don't Fragment\n");
    printf("  %s -f 2001:4860:4860::8888 2000\n\n", prog_name);
    printf("Note: This tool requires root privileges\n");
    printf("      Run with: sudo %s [options] <args>\n", prog_name);
}

int send_icmpv6_echo(test_config_t *config, int seq) {
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock < 0) {
        perror("Socket creation failed (need root privileges)");
        return -1;
    }

    // Bind to source address if specified
    if (config->src_addr != NULL) {
        struct sockaddr_in6 src_sockaddr;
        memset(&src_sockaddr, 0, sizeof(src_sockaddr));
        src_sockaddr.sin6_family = AF_INET6;

        // Parse source address (handle interface specification)
        char src_addr_copy[INET6_ADDRSTRLEN + 20];
        strncpy(src_addr_copy, config->src_addr, sizeof(src_addr_copy) - 1);
        src_addr_copy[sizeof(src_addr_copy) - 1] = '\0';

        // Check for interface specification (e.g., fe80::1%eth0)
        char *percent = strchr(src_addr_copy, '%');
        if (percent != NULL) {
            *percent = '\0';
            char *if_name = percent + 1;
            // Get interface index
            unsigned int if_index = if_nametoindex(if_name);
            if (if_index == 0) {
                fprintf(stderr, "Invalid interface: %s\n", if_name);
                close(sock);
                return -1;
            }
            src_sockaddr.sin6_scope_id = if_index;
        }

        if (inet_pton(AF_INET6, src_addr_copy, &src_sockaddr.sin6_addr) <= 0) {
            fprintf(stderr, "Invalid source IPv6 address: %s\n", config->src_addr);
            close(sock);
            return -1;
        }

        if (bind(sock, (struct sockaddr *)&src_sockaddr, sizeof(src_sockaddr)) < 0) {
            perror("Failed to bind to source address");
            fprintf(stderr, "Source address: %s\n", config->src_addr);
            close(sock);
            return -1;
        }
    }

    // Set Don't Fragment option if requested
    if (config->dontfrag) {
#ifdef IPV6_DONTFRAG
        int dontfrag = 1;
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_DONTFRAG, &dontfrag, sizeof(dontfrag)) < 0) {
            perror("Warning: Failed to set IPV6_DONTFRAG");
            fprintf(stderr, "Your system may not support IPV6_DONTFRAG option\n");
        } else {
            printf("Don't Fragment enabled\n");
        }
#else
        fprintf(stderr, "Warning: IPV6_DONTFRAG not supported on this system\n");
        fprintf(stderr, "Fragmentation may still occur\n");
#endif
    }

    // Set up destination address
    struct sockaddr_in6 dest_sockaddr;
    memset(&dest_sockaddr, 0, sizeof(dest_sockaddr));
    dest_sockaddr.sin6_family = AF_INET6;

    // Parse destination address (handle interface specification)
    char dest_addr_copy[INET6_ADDRSTRLEN + 20];
    strncpy(dest_addr_copy, config->dest_addr, sizeof(dest_addr_copy) - 1);
    dest_addr_copy[sizeof(dest_addr_copy) - 1] = '\0';

    char *percent = strchr(dest_addr_copy, '%');
    if (percent != NULL) {
        *percent = '\0';
        char *if_name = percent + 1;
        unsigned int if_index = if_nametoindex(if_name);
        if (if_index == 0) {
            fprintf(stderr, "Invalid interface: %s\n", if_name);
            close(sock);
            return -1;
        }
        dest_sockaddr.sin6_scope_id = if_index;
    }

    if (inet_pton(AF_INET6, dest_addr_copy, &dest_sockaddr.sin6_addr) <= 0) {
        fprintf(stderr, "Invalid destination IPv6 address: %s\n", config->dest_addr);
        close(sock);
        return -1;
    }

    // Create ICMP packet
    char packet[PACKET_SIZE];
    memset(packet, 0, PACKET_SIZE);

    struct icmp6_hdr *icmp = (struct icmp6_hdr *)packet;
    icmp->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp->icmp6_code = 0;
    icmp->icmp6_id = htons(getpid() & 0xFFFF);
    icmp->icmp6_seq = htons(seq);

    // Fill payload with pattern
    int payload_size = config->packet_size - sizeof(struct icmp6_hdr);
    if (payload_size > 0) {
        memset(packet + sizeof(struct icmp6_hdr), 'A', payload_size);
    }

    // Checksum will be calculated by kernel for ICMPv6
    icmp->icmp6_cksum = 0;

    printf("\n[%d] Sending... (size: %d bytes)\n", seq, config->packet_size);

    struct timeval start, end;
    gettimeofday(&start, NULL);

    if (sendto(sock, packet, config->packet_size, 0,
               (struct sockaddr *)&dest_sockaddr, sizeof(dest_sockaddr)) < 0) {
        perror("Send failed");
        close(sock);
        return -1;
    }

    // Set receive timeout
    struct timeval timeout;
    timeout.tv_sec = config->timeout;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Receive response
    char recv_packet[PACKET_SIZE];
    struct sockaddr_in6 recv_addr;
    socklen_t addr_len = sizeof(recv_addr);

    int recv_len = recvfrom(sock, recv_packet, PACKET_SIZE, 0,
                            (struct sockaddr *)&recv_addr, &addr_len);

    if (recv_len > 0) {
        gettimeofday(&end, NULL);
        double elapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                        (end.tv_usec - start.tv_usec) / 1000.0;

        struct icmp6_hdr *recv_icmp = (struct icmp6_hdr *)recv_packet;
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &recv_addr.sin6_addr, addr_str, INET6_ADDRSTRLEN);

        if (recv_icmp->icmp6_type == ICMP6_ECHO_REPLY) {
            printf("[✓] Reply received: %s → seq=%d, time=%.2f ms, size=%d bytes\n",
                   addr_str, seq, elapsed, recv_len);
            close(sock);
            return 0;
        } else if (recv_icmp->icmp6_type == ICMP6_PACKET_TOO_BIG) {
            printf("[!] Packet Too Big received: seq=%d\n", seq);
            printf("    (Ignoring and continuing)\n");
            close(sock);
            return 1;
        } else if (recv_icmp->icmp6_type == ICMP6_DST_UNREACH) {
            printf("[!] Destination Unreachable: seq=%d\n", seq);
            close(sock);
            return 1;
        } else if (recv_icmp->icmp6_type == ICMP6_TIME_EXCEEDED) {
            printf("[!] Time Exceeded: seq=%d\n", seq);
            close(sock);
            return 1;
        } else {
            printf("[?] Unexpected ICMP type %d: seq=%d\n",
                   recv_icmp->icmp6_type, seq);
            close(sock);
            return 1;
        }
    } else {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("[✗] No response: seq=%d (timeout)\n", seq);
        } else {
            perror("Receive error");
        }
        close(sock);
        return 1;
    }

    close(sock);
    return 0;
}

int main(int argc, char *argv[]) {
    test_config_t config;
    config.src_addr = NULL;
    config.dest_addr = NULL;
    config.packet_size = 0;
    config.count = DEFAULT_COUNT;
    config.timeout = DEFAULT_TIMEOUT;
    config.dontfrag = 0;

    int opt;
    while ((opt = getopt(argc, argv, "s:c:t:fh")) != -1) {
        switch (opt) {
            case 's':
                config.src_addr = optarg;
                break;
            case 'c':
                config.count = atoi(optarg);
                if (config.count < 1 || config.count > 10000) {
                    fprintf(stderr, "Error: Count must be between 1 and 10000\n");
                    return 1;
                }
                break;
            case 't':
                config.timeout = atoi(optarg);
                if (config.timeout < 1 || config.timeout > 60) {
                    fprintf(stderr, "Error: Timeout must be between 1 and 60 seconds\n");
                    return 1;
                }
                break;
            case 'f':
                config.dontfrag = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Parse positional arguments
    if (optind + 2 > argc) {
        fprintf(stderr, "Error: Missing required arguments\n\n");
        print_usage(argv[0]);
        return 1;
    }

    config.dest_addr = argv[optind];
    config.packet_size = atoi(argv[optind + 1]);

    if (config.packet_size < 8 || config.packet_size > PACKET_SIZE) {
        fprintf(stderr, "Error: Packet size must be between 8 and %d bytes\n", PACKET_SIZE);
        return 1;
    }

    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This program requires root privileges\n");
        fprintf(stderr, "Please run with sudo: sudo %s", argv[0]);
        for (int i = 1; i < argc; i++) {
            fprintf(stderr, " %s", argv[i]);
        }
        fprintf(stderr, "\n");
        return 1;
    }

    printf("============================================================\n");
    printf("ICMPv6 Echo Request Test\n");
    printf("============================================================\n");
    if (config.src_addr) {
        printf("Source:      %s\n", config.src_addr);
    }
    printf("Destination: %s\n", config.dest_addr);
    printf("Packet size: %d bytes\n", config.packet_size);
    printf("Count:       %d\n", config.count);
    printf("Timeout:     %d seconds\n", config.timeout);
    printf("Don't Frag:  %s\n", config.dontfrag ? "Enabled" : "Disabled");
    printf("------------------------------------------------------------\n");

    int sent = 0, received = 0, lost = 0;

    for (int i = 1; i <= config.count; i++) {
        int result = send_icmpv6_echo(&config, i);
        sent++;

        if (result == 0) {
            received++;
        } else {
            lost++;
        }

        if (i < config.count) {
            usleep(200000); // 200ms delay between packets
        }
    }

    printf("\n============================================================\n");
    printf("Statistics:\n");
    printf("  Sent:     %d packets\n", sent);
    printf("  Received: %d packets\n", received);
    if (sent > 0) {
        printf("  Lost:     %d packets (%.1f%% loss)\n",
               lost, (lost * 100.0) / sent);
    } else {
        printf("  Lost:     0 packets\n");
    }
    printf("============================================================\n");

    return 0;
}
