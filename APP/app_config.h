#ifndef APP_CONFIG_H
#define APP_CONFIG_H
#include <stddef.h>
#include <stdio.h>

typedef unsigned long      long uint64_t;
typedef unsigned           char uint8_t;
typedef unsigned short     int  uint16_t;
typedef unsigned           int  uint32_t;
typedef signed             int  ssize_t;

#define alignment_ok(p, n) ((size_t)(p) % (n) == 0)


#endif /*APP_CONFIG_H*/

