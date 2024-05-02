#ifndef KCALL_ARM64_H
#define KCALL_ARM64_H

#ifndef __arm64e__

#include <stdint.h>
#include <stdbool.h>
#include <mach/mach.h>
#include <pthread.h>
#include "kernel.h"
#include "primitives.h"

typedef struct {
	bool inited;
	pthread_mutex_t lock;
	dispatch_semaphore_t semaphore;
	thread_t thread;
	uint64_t actContext;
	uint64_t kernelStack;
	kRegisterState *alignedState;
} arm64KcallThread;

void arm64_kcall_return(void);

int arm64_kcall_init(void);

#endif

#endif