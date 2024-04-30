#ifndef KCALL_FUGU14_H
#define KCALL_FUGU14_H

#include <stdint.h>
#include <stdbool.h>
#include <mach/mach.h>
#include <pthread.h>
#include "kernel.h"
#include "primitives.h"

typedef struct {
	bool inited;
	pthread_mutex_t lock;
	thread_t thread;
	uint64_t actContext;
	kRegisterState signedState;
	uint64_t kernelStack;
	kRegisterState *mappedState;
	uint64_t scratchMemory;
	uint64_t *scratchMemoryMapped;
} Fugu14KcallThread;

int fugu14_kcall_init(int (^threadSigner)(mach_port_t threadPort));
int jbclient_get_fugu14_kcall(void);


#endif