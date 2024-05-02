#ifndef PHYSRW_H
#define PHYSRW_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "info.h"

#define PPLRW_USER_MAPPING_OFFSET   (L1_BLOCK_SIZE * L1_BLOCK_COUNT) - 0x1000000000
#define PPLRW_USER_MAPPING_TTEP_IDX (PPLRW_USER_MAPPING_OFFSET / L1_BLOCK_SIZE)

int physrw_handoff(pid_t pid);
int libjailbreak_physrw_init(bool receivedHandoff);

#endif
