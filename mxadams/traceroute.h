#ifndef HEADER_H
#define HEADER_H

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

inline int LOG_LEVEL = 0;
#define TRACE                                                                  \
  if (LOG_LEVEL > 5) {                                                         \
  std::cout << "TRACE: "
#define DEBUG                                                                  \
  if (LOG_LEVEL > 4) {                                                         \
  std::cout << "DEBUG: "
#define INFO                                                                   \
  if (LOG_LEVEL > 3) {                                                         \
  std::cout << "INFO: "
#define WARNING                                                                \
  if (LOG_LEVEL > 2) {                                                         \
  std::cout << "WARNING: "
#define ERROR                                                                  \
  if (LOG_LEVEL > 1) {                                                         \
  std::cout << "ERROR: "
#define FATAL                                                                  \
  if (LOG_LEVEL > 0) {                                                         \
  std::cout << "FATAL: "
#define ENDL                                                                   \
  " (" << __FILE__ << ":" << __LINE__ << ")" << std::endl;                     \
  }

uint16_t checksum(unsigned short *buffer, int size);

#endif
