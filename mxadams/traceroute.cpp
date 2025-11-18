#include "traceroute.h"

// ****************************************************************************
// * Compute the Internet Checksum over an arbitrary buffer.
// * (written with the help of ChatGPT 3.5)
// ****************************************************************************
uint16_t checksum(unsigned short *buffer, int size) {
  unsigned long sum = 0;
  while (size > 1) {
    sum += *buffer++;
    size -= 2;
  }
  if (size == 1) {
    sum += *(unsigned char *)buffer;
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

struct packet_t {
  struct iphdr ip_header;
  struct icmphdr icmp_header;
  char payload[36];
};

void build_echo_request(packet_t *packet, uint16_t sequence, uint8_t ttl) {
  packet->ip_header.version = 4;
  packet->ip_header.ihl = 5;
  packet->ip_header.tos = 0;
  packet->ip_header.tot_len = htons(sizeof(packet_t));
  packet->ip_header.id = htons(getpid() & 0xFFFF);
  packet->ip_header.frag_off = 0;
  packet->ip_header.ttl = ttl;
  packet->ip_header.protocol = IPPROTO_ICMP;
  packet->ip_header.check = 0;
  packet->icmp_header.type = ICMP_ECHO;
  packet->icmp_header.code = 0;
  packet->icmp_header.un.echo.id = htons(getpid());
  packet->icmp_header.un.echo.sequence = htons(sequence);
  packet->icmp_header.checksum = 0;
  memset(packet->payload, 'A', sizeof(packet->payload));
  packet->icmp_header.checksum =
      checksum((unsigned short *)&packet->icmp_header,
               sizeof(packet->icmp_header) + sizeof(packet->payload));
}

bool is_our_packet(const char *receive_buf, int receive_len,
                   uint16_t expected_id) {
  if (receive_len < (int)(sizeof(struct iphdr) + sizeof(struct icmphdr))) {
    return false;
  }
  struct iphdr *receive_ip = (struct iphdr *)receive_buf;
  int ip_header_len = receive_ip->ihl * 4;
  if (receive_len < ip_header_len + (int)sizeof(struct icmphdr)) {
    return false;
  }
  struct icmphdr *receive_icmp =
      (struct icmphdr *)(receive_buf + (receive_ip->ihl * 4));
  if (receive_icmp->type == ICMP_ECHOREPLY) {
    DEBUG << "Received ICMP Echo Reply, checking ID: "
          << ntohs(receive_icmp->un.echo.id) << " vs. expected: " << expected_id
          << ENDL;
    return ntohs(receive_icmp->un.echo.id) == expected_id;
  }
  if (receive_icmp->type == ICMP_TIME_EXCEEDED &&
      receive_icmp->code == ICMP_EXC_TTL) {
    DEBUG << "Received ICMP Time Exceeded, checking embedded packet ID" << ENDL;
    char *embedded_data =
        (char *)(receive_buf + ip_header_len + sizeof(struct icmphdr));
    if (receive_len < ip_header_len + (int)sizeof(struct icmphdr) +
                          (int)sizeof(struct iphdr)) {
      return false;
    }
    struct iphdr *embedded_ip = (struct iphdr *)embedded_data;
    int embedded_ip_len = embedded_ip->ihl * 4;
    if (receive_len < ip_header_len + (int)sizeof(struct icmphdr) +
                          embedded_ip_len + (int)sizeof(struct icmphdr)) {
      return false;
    }
    struct icmphdr *embedded_icmp =
        (struct icmphdr *)((char *)embedded_ip + (embedded_ip->ihl * 4));
    if (embedded_icmp->type == ICMP_ECHO) {
      DEBUG << "Embedded packet is ICMP Echo Request, checking ID: "
            << ntohs(embedded_icmp->un.echo.id)
            << " vs. expected: " << expected_id << ENDL;
      return ntohs(embedded_icmp->un.echo.id) == expected_id;
    }
  }
  return false;
}

int waitForResponse(int receive_socket, uint16_t expected_id, uint8_t ttl,
                    struct sockaddr_in *dest_sddr, bool &got_reply) {
  fd_set read_fds;
  struct timeval timeout;
  int select_return_val;
  char receive_buf[1024];
  struct sockaddr_in receive_addr;
  socklen_t addr_len = sizeof(receive_addr);
  struct timeval start_time, current_time;
  gettimeofday(&start_time, NULL);
  while (true) {
    gettimeofday(&current_time, NULL);
    double elapsed = (current_time.tv_sec - start_time.tv_sec) +
                     (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
    if (elapsed >= 15.0) {
      std::cout << "No response with ttl=" << (int)ttl << std::endl;
      return 0;
    }
    double remaining = 15.0 - elapsed;
    if (remaining > 5.0) {
      remaining = 5.0;
    }
    timeout.tv_sec = (int)remaining;
    timeout.tv_usec = (int)((remaining - timeout.tv_sec) * 1000000);
    FD_ZERO(&read_fds);
    FD_SET(receive_socket, &read_fds);
    DEBUG << "Waiting up to " << remaining << " seconds for reply" << ENDL;
    select_return_val =
        select(receive_socket + 1, &read_fds, NULL, NULL, &timeout);
    if (select_return_val < 0) {
      perror("select error");
      return -1;
    } else if (select_return_val == 0) {
      continue;
    } else {
      if (FD_ISSET(receive_socket, &read_fds)) {
        int receive_len =
            recvfrom(receive_socket, receive_buf, sizeof(receive_buf), 0,
                     (struct sockaddr *)&receive_addr, &addr_len);
        if (receive_len < 0) {
          perror("receivefrom error");
          return -1;
        }
        DEBUG << "Received packet of length " << receive_len << ENDL;
        if (is_our_packet(receive_buf, receive_len, expected_id)) {
          struct iphdr *receive_ip = (struct iphdr *)receive_buf;
          struct icmphdr *receive_icmp =
              (struct icmphdr *)(receive_buf + (receive_ip->ihl * 4));
          char respondent_ip[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &receive_addr.sin_addr, respondent_ip,
                    INET_ADDRSTRLEN);
          if (receive_icmp->type == ICMP_ECHOREPLY) {
            std::cout << "Reached destination " << respondent_ip
                      << " ttl=" << (int)ttl << std::endl;
            got_reply = true;
            return 1;
          } else if (receive_icmp->type == ICMP_TIME_EXCEEDED) {
            std::cout << "Reply from " << respondent_ip << " ttl=" << (int)ttl
                      << std::endl;
            return 1;
          }
        } else {
          DEBUG << "Received packet is not for us, ignoring." << ENDL;
        }
      }
    }
  }
}

int main(int argc, char *argv[]) {
  std::string destIP;

  // ********************************************************************
  // * Process the command line arguments
  // ********************************************************************
  int opt = 0;
  while ((opt = getopt(argc, argv, "t:d:")) != -1) {

    switch (opt) {
    case 't':
      destIP = optarg;
      break;
    case 'd':
      LOG_LEVEL = atoi(optarg);
      ;
      break;
    case ':':
    case '?':
    default:
      std::cout << "useage: " << argv[0] << " -t [target ip] -d [Debug Level]"
                << std::endl;
      exit(-1);
    }
  }

  // ********************************************************************
  // * Traceroute Functionality
  // ********************************************************************
  int max_num_hops = 30;
  uint16_t extected_id = getpid();
  if (destIP.empty()) {
    std::cerr << "Destination IP is required. Use -t [target ip]" << std::endl;
    return -1;
  }
  INFO << "Starting traceroute to " << destIP << ENDL;
  int send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (send_socket < 0) {
    perror("send socket creation failed");
    return -1;
  }
  int receive_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (receive_socket < 0) {
    perror("receive socket creation failed");
    close(send_socket);
    return -1;
  }
  struct sockaddr_in dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = inet_addr(destIP.c_str());
  if (dest_addr.sin_addr.s_addr == INADDR_NONE) {
    std::cerr << "Invalid destination IP address." << std::endl;
    close(send_socket);
    close(receive_socket);
    return -1;
  }
  INFO << "Destination IP: " << destIP << " (" << dest_addr.sin_addr.s_addr
       << ")" << ENDL;
  bool destination_reached = false;
  for (uint8_t ttl = 2; ttl <= max_num_hops + 1 && !destination_reached;
       ttl++) {
    DEBUG << "Sending packet with TTL=" << (int)ttl << ENDL;
    packet_t packet;
    build_echo_request(&packet, ttl, ttl);
    packet.ip_header.daddr = dest_addr.sin_addr.s_addr;
    if (sendto(send_socket, &packet, sizeof(packet), 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
      perror("sendto failed");
      close(send_socket);
      close(receive_socket);
      return -1;
    }
    DEBUG << "Sent ICMP Echo Request with TTL=" << (int)ttl << ENDL;
    bool got_reply = false;
    int result = waitForResponse(receive_socket, extected_id, ttl, &dest_addr,
                                 got_reply);
    if (result < 0) {
      perror("Error while waiting for response");
      close(send_socket);
      close(receive_socket);
      return -1;
    }
    if (got_reply) {
      destination_reached = true;
      break;
    }
  }
  if (!destination_reached) {
    std::cout << "Traceroute complete, destination not reached within "
              << max_num_hops << " hops." << std::endl;
  }
  close(send_socket);
  close(receive_socket);
  INFO << "Traceroute finished." << ENDL;
  return 0;
}