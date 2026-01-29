#ifndef _RB_ARC4RANDOM_H
#define _RB_ARC4RANDOM 1

#include "libratbox_config.h"
#include "ratbox_lib.h"

extern void arc4random_stir(void);
extern uint32_t arc4random(void);
extern void arc4random_addrandom(uint8_t *dat, int datlen);

#endif
