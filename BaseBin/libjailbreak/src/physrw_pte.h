#ifndef PHYSRW_PTE_H
#define PHYSRW_PTE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

int physrw_pte_handoff(pid_t pid, uint64_t *swAsidPtr);
int libjailbreak_physrw_pte_init(bool receivedHandoff, uint64_t asidPtr);
bool device_supports_physrw_pte(void);

#endif