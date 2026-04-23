#ifndef __STAT_H__
#define __STAT_H__
 
#include "types.h"
 
#define DIR      0x040000
#define FILE     0x100000
 
struct Stat {
    uint64 dev;
    uint64 ino;
    uint32 mode;
    uint32 nlink;
    uint64 pad[7];
};

#endif