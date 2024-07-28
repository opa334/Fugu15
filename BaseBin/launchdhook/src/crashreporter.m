#include "crashreporter.h"
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <pthread/stack_np.h>
#include <pthread/pthread.h>
#include <mach/exception_types.h>
#include <sys/utsname.h>
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/dyld.h>
extern CFStringRef CFCopySystemVersionString(void);

void abort_with_reason(uint32_t reason_namespace, uint64_t reason_code, const char *reason_string, uint64_t reason_flags);

#import <Foundation/Foundation.h>

static NSUncaughtExceptionHandler* defaultNSExceptionHandler = NULL;

#define	INSTACK(a)	((a) >= stackbot && (a) <= stacktop)
#if defined(__x86_64__)
#define	ISALIGNED(a)	((((uintptr_t)(a)) & 0xf) == 0)
#elif defined(__i386__)
#define	ISALIGNED(a)	((((uintptr_t)(a)) & 0xf) == 8)
#elif defined(__arm__) || defined(__arm64__)
#define	ISALIGNED(a)	((((uintptr_t)(a)) & 0x1) == 0)
#endif

#define EXC_MASK_CRASH_RELATED (EXC_MASK_BAD_ACCESS | \
		EXC_MASK_BAD_INSTRUCTION |			  \
		EXC_MASK_ARITHMETIC |				  \
		EXC_MASK_EMULATION |				  \
		EXC_MASK_SOFTWARE |					  \
		EXC_MASK_BREAKPOINT)

__attribute__((noinline))
static void pthread_backtrace(pthread_t pthread, vm_address_t *buffer, unsigned max, unsigned *nb,
		unsigned skip, void *startfp)
{
	void *frame, *next;
	void *stacktop = pthread_get_stackaddr_np(pthread);
	void *stackbot = stacktop - pthread_get_stacksize_np(pthread);

	*nb = 0;

	// Rely on the fact that our caller has an empty stackframe (no local vars)
	// to determine the minimum size of a stackframe (frame ptr & return addr)
	frame = startfp;
	next = (void*)pthread_stack_frame_decode_np((uintptr_t)frame, NULL);

	/* make sure return address is never out of bounds */
	stacktop -= (next - frame);

	if(!INSTACK(frame) || !ISALIGNED(frame))
		return;
	while (startfp || skip--) {
		if (startfp && startfp < next) break;
		if(!INSTACK(next) || !ISALIGNED(next) || next <= frame)
			return;
		frame = next;
		next = (void*)pthread_stack_frame_decode_np((uintptr_t)frame, NULL);
	}
	while (max--) {
		uintptr_t retaddr;
		next = (void*)pthread_stack_frame_decode_np((uintptr_t)frame, &retaddr);
		buffer[*nb] = retaddr;
		(*nb)++;
		if(!INSTACK(next) || !ISALIGNED(next) || next <= frame)
			return;
		frame = next;
	}
}

static crash_reporter_state gCrashReporterState = kCrashReporterStateNotActive;
mach_port_t gExceptionPort = MACH_PORT_NULL;
dispatch_queue_t gExceptionQueue = NULL;
pthread_t gExceptionThread = 0;

const char *crashreporter_string_for_code(int code)
{
	switch (code)
	{
		case EXC_BAD_ACCESS:
		return "EXC_BAD_ACCESS";

		case EXC_BAD_INSTRUCTION:
		return "EXC_BAD_INSTRUCTION";

		case EXC_ARITHMETIC:
		return "EXC_ARITHMETIC";

		case EXC_EMULATION:
		return "EXC_EMULATION";

		case EXC_SOFTWARE:
		return "EXC_SOFTWARE";
	
		case EXC_BREAKPOINT:
		return "EXC_BREAKPOINT";

		case EXC_SYSCALL:
		return "EXC_SYSCALL";

		case EXC_MACH_SYSCALL:
		return "EXC_MACH_SYSCALL";

		case EXC_RPC_ALERT:
		return "EXC_RPC_ALERT";

		case EXC_CRASH:
		return "EXC_CRASH";

		case EXC_RESOURCE:
		return "EXC_RESOURCE";

		case EXC_GUARD:
		return "EXC_GUARD";

		case EXC_CORPSE_NOTIFY:
		return "EXC_CORPSE_NOTIFY";
	}
	return NULL;
}

void crashreporter_dump_backtrace_line(FILE *f, vm_address_t addr)
{
	Dl_info info;
	if (dladdr((void *)addr, &info) != 0) {
		const char *sname = info.dli_sname;
		const char *fname = info.dli_fname;
		if (!sname) {
			sname = "<unexported>";
		}

		fprintf(f, "0x%lX: %s (0x%lX + 0x%lX) (%s(0x%lX) + 0x%lX)\n", addr, sname, (vm_address_t)info.dli_saddr, addr - (vm_address_t)info.dli_saddr, fname, (vm_address_t)info.dli_fbase, addr - (vm_address_t)info.dli_fbase);
	}
	else {
		fprintf(f, "0x%lX (no association)\n", addr);
	}
}

FILE *crashreporter_open_outfile(const char *source, char **nameOut)
{
	time_t t = time(NULL);
	char timestamp[64];
	sprintf(&timestamp[0], "%lu", t);

	char *name = malloc(100);
	strlcpy(name, source, 100);
	strlcat(name, "-", 100);
	strlcat(name, timestamp, 100);
	strlcat(name, ".ips", 100);

	char dumpPath[PATH_MAX];
	strlcpy(dumpPath, "/var/mobile/Library/Logs/CrashReporter/", PATH_MAX);
	strlcat(dumpPath, name, PATH_MAX);

	if (nameOut) {
		*nameOut = name;
	}
	else {
		free(name);
	}

	FILE *f = fopen(dumpPath, "w");
	if (f) {
		struct utsname systemInfo;
		uname(&systemInfo);

		fprintf(f, "Device Model:   %s\n", systemInfo.machine);

		CFStringRef deviceVersion = CFCopySystemVersionString();
		if (deviceVersion) {
			fprintf(f, "Device Version: %s\n", CFStringGetCStringPtr(deviceVersion, kCFStringEncodingUTF8));
			CFRelease(deviceVersion);
		}

	#ifdef __arm64e__
		fprintf(f, "Architecture:   arm64e\n");
	#else
		fprintf(f, "Architecture:   arm64\n");
	#endif
		fprintf(f, "\n");
	}

	return f;
}

void crashreporter_save_outfile(FILE *f)
{
	fflush(f);
	fchown(fileno(f), 0, 250);
	fchmod(fileno(f), 00660);
	if (fcntl(fileno(f), F_FULLFSYNC) != 0) {
		fsync(fileno(f));
	}
	fclose(f);

	int dir = open("/var/mobile/Library/Logs/CrashReporter", O_RDONLY | O_DIRECTORY);
	if (dir >= 0) {
		if (fcntl(dir, F_FULLFSYNC) != 0) {
			fsync(dir);
		}
		close(dir);
	}
}

void crashreporter_dump_mach(FILE *f, int code, int subcode, arm_thread_state64_t threadState, arm_exception_state64_t exceptionState, vm_address_t *bt)
{
	fprintf(f, "Exception:         %s\n", crashreporter_string_for_code(code));
	fprintf(f, "Exception Subcode: %d\n", subcode);
	fprintf(f, "\n");

	fprintf(f, "Register State:\n");
	uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(threadState);
	uint64_t lr = (uint64_t)__darwin_arm_thread_state64_get_lr(threadState);

	for(int i = 0; i <= 28; i++) {
		if (i < 10) {
			fprintf(f, " ");
		}
		fprintf(f, "x%d = 0x%016llX", i, threadState.__x[i]);
		if ((i+1) % (6+1) == 0) {
			fprintf(f, "\n");
		}
		else {
			fprintf(f, ", ");
		}
	}
	fprintf(f, " lr = 0x%016llX,  pc = 0x%016llX,  sp = 0x%016llX,  fp = 0x%016llX, cpsr=         0x%08X, far = 0x%016llX\n\n", lr, pc, (uint64_t)__darwin_arm_thread_state64_get_sp(threadState), (uint64_t)__darwin_arm_thread_state64_get_fp(threadState), threadState.__cpsr, exceptionState.__far);

	fprintf(f, "Backtrace:\n");
	crashreporter_dump_backtrace_line(f, (vm_address_t)pc);
	crashreporter_dump_backtrace_line(f, (vm_address_t)lr);
	int btIdx = 0;
	vm_address_t btAddr = bt[btIdx++];
	while (btAddr != 0) {
		crashreporter_dump_backtrace_line(f, btAddr);
		btAddr = bt[btIdx++];
	}
	fprintf(f, "\n");
}

void crashreporter_dump_image_list(FILE *f)
{
	fprintf(f, "Images:\n");
	for (uint32_t i = 0; i < _dyld_image_count(); i++) {
		fprintf(f, "%s: %p\n", _dyld_get_image_name(i), _dyld_get_image_header(i));
	}
}

void crashreporter_catch_mach(exception_raise_request *request, exception_raise_reply *reply)
{
	pthread_t pthread = pthread_from_mach_thread_np(request->thread.name);

	mach_msg_type_number_t threadStateCount = ARM_THREAD_STATE64_COUNT;
	arm_thread_state64_t threadState;
	thread_get_state(request->thread.name, ARM_THREAD_STATE64, (thread_state_t)&threadState, &threadStateCount);

	arm_exception_state64_t exceptionState;
	mach_msg_type_number_t exceptionStateCount = ARM_EXCEPTION_STATE64_COUNT;
	thread_get_state(request->thread.name, ARM_EXCEPTION_STATE64, (thread_state_t)&exceptionState, &exceptionStateCount);

	reply->ndr = request->ndr;
	reply->retcode = KERN_FAILURE;

	vm_address_t *bt = malloc(100 * sizeof(vm_address_t));
	memset(bt, 0, 100 * sizeof(vm_address_t));
	unsigned c = 100;
	pthread_backtrace(pthread, bt, c, &c, 0, (void *)__darwin_arm_thread_state64_get_fp(threadState));

	char *name = NULL;
	FILE *f = crashreporter_open_outfile("launchd", &name);
	if (f) {
		crashreporter_dump_mach(f, request->code, request->subcode, threadState, exceptionState, bt);
		crashreporter_dump_image_list(f);
		crashreporter_save_outfile(f);
	}

	if (name) {
		char msg[1000];
		snprintf(msg, 1000, "Mach exception occured. A detailed report has been written to the file %s.", name);
		abort_with_reason(7, 1, msg, 0);
	}
	else {
		abort_with_reason(7, 1, "Mach exception occured. Failed to write the detailed report to a file.", 0);
	}
}

void crashreporter_dump_objc(FILE *f, NSException *e)
{
	@autoreleasepool {
		fprintf(f, "Exception:         %s\n", e.name.UTF8String);
		fprintf(f, "Exception Reason:  %s\n", e.reason.UTF8String);
		fprintf(f, "User Info:         %s\n", e.userInfo.description.UTF8String);
		fprintf(f, "\n");

		if (e.callStackReturnAddresses.count) {
			fprintf(f, "Backtrace:\n");
			for (NSNumber *btAddrNum in e.callStackReturnAddresses) {
				crashreporter_dump_backtrace_line(f, [btAddrNum unsignedLongLongValue]);
			}
			fprintf(f, "\n");
		}
		else if (e.callStackSymbols.count) {
			fprintf(f, "Backtrace:\n");
			for (NSString *symbol in e.callStackSymbols) {
				fprintf(f, "%s\n", symbol.UTF8String);
			}
			fprintf(f, "\n");
		} 
	}
}

void crashreporter_catch_objc(NSException *e)
{
	@autoreleasepool {
		static BOOL hasCrashed = NO;
		if (hasCrashed) {
			exit(187);
		}
		else {
			hasCrashed = YES;
		}

		char *name = NULL;
		FILE *f = crashreporter_open_outfile("launchd", &name);
		if (f) {
			@try {
				crashreporter_dump_objc(f, e);
				crashreporter_dump_image_list(f);
			}
			@catch (NSException *e2) {
				exit(187);
			}
			crashreporter_save_outfile(f);
		}
		if (name) {
			char msg[1000];
			snprintf(msg, 1000, "Objective-C exception occured. A detailed report has been written to the file %s.", name);
			abort_with_reason(7, 1, msg, 0);
		}
		else {
			abort_with_reason(7, 1, "Objective-C exception occured. Failed to write the detailed report to a file.", 0);
		}
	}
}

void *crashreporter_listen(void *arg)
{
	while (true) {
		mach_msg_header_t msg;
		msg.msgh_local_port = gExceptionPort;
		msg.msgh_size = 1024;
		mach_msg_receive(&msg);

		exception_raise_reply reply;
		crashreporter_catch_mach((exception_raise_request *)&msg, &reply);

		reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(msg.msgh_bits), 0);
		reply.header.msgh_size = sizeof(exception_raise_reply);
		reply.header.msgh_remote_port = msg.msgh_remote_port;
		reply.header.msgh_local_port = MACH_PORT_NULL;
		reply.header.msgh_id = msg.msgh_id + 0x64;

		mach_msg(&reply.header, MACH_SEND_MSG | MACH_MSG_OPTION_NONE, reply.header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	}
}

void crashreporter_pause(void)
{
	if (gCrashReporterState == kCrashReporterStateActive) {
		task_set_exception_ports(mach_task_self_, EXC_MASK_CRASH_RELATED, 0, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
		NSSetUncaughtExceptionHandler(defaultNSExceptionHandler);
		defaultNSExceptionHandler = nil;
		gCrashReporterState = kCrashReporterStatePaused;
	}
}

void crashreporter_resume(void)
{
	if (gCrashReporterState == kCrashReporterStatePaused) {
		task_set_exception_ports(mach_task_self_, EXC_MASK_CRASH_RELATED, gExceptionPort, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
		defaultNSExceptionHandler = NSGetUncaughtExceptionHandler();
		NSSetUncaughtExceptionHandler(crashreporter_catch_objc);
		gCrashReporterState = kCrashReporterStateActive;
	}
}

void crashreporter_start(void)
{
	if (gCrashReporterState == kCrashReporterStateNotActive) {
		mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &gExceptionPort);
		mach_port_insert_right(mach_task_self_, gExceptionPort, gExceptionPort, MACH_MSG_TYPE_MAKE_SEND);
		pthread_create(&gExceptionThread, NULL, crashreporter_listen, "crashreporter");
		gCrashReporterState = kCrashReporterStatePaused;
		crashreporter_resume();
	}
}

