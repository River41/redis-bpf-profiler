#ifndef __REDIS_METADATA_H
#define __REDIS_METADATA_H

struct event {
    char cmd[16];      // Command name like "SET"
    unsigned int argc; // Number of arguments
    unsigned long long latency_ns; // Time taken（ns）
};

#endif