#include <spawn.h>
#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/jbserver.h>
#include <libjailbreak/jbserver_boomerang.h>
#include <libjailbreak/physrw.h>
#include <libjailbreak/physrw_pte.h>
#include <libjailbreak/primitives_IOSurface.h>
#include <libjailbreak/kalloc_pt.h>
#include <libjailbreak/kcall_Fugu14.h>
#include <libjailbreak/kcall_arm64.h>
#include <unistd.h>

int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *__restrict attr, mach_port_t portarray[], uint32_t count);

#define JB_DOMAIN_PRIMITIVE_STORAGE 10

#define JB_PRIMITIVE_STORAGE_RETRIEVE_PHYSRW 1
#define JB_PRIMITIVE_STORAGE_RETRIEVE_KCALL 2

void boomerang_stashPrimitives()
{
	dispatch_semaphore_t boomerangDone = dispatch_semaphore_create(0);

	mach_port_t serverPort = MACH_PORT_NULL;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
	mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);

	// Small server provided to boomerang to obtain exploit primitives
	dispatch_source_t serverSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)serverPort, 0, dispatch_get_main_queue());
	dispatch_source_set_event_handler(serverSource, ^{
		xpc_object_t xdict = NULL;
		if (!xpc_pipe_receive(serverPort, &xdict)) {
			if (jbserver_received_boomerang_xpc_message(&gBoomerangServer, xdict) == JBS_BOOMERANG_DONE) {
				dispatch_semaphore_signal(boomerangDone);
			}
			xpc_release(xdict);
		}
	});
	dispatch_resume(serverSource);

	// Spawn boomerang process
	pid_t boomerangPid = 0;
	posix_spawnattr_t attr = NULL;
	posix_spawnattr_init(&attr);
	posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ MACH_PORT_NULL, MACH_PORT_NULL, serverPort }, 3);
	int ret = posix_spawn(&boomerangPid, JBROOT_PATH("/basebin/boomerang"), NULL, &attr, NULL, NULL);
	if (ret != 0) return;
	posix_spawnattr_destroy(&attr);

	// Wait for boomerang to retrieve the primitives from launchd (handled in server above)
	dispatch_semaphore_wait(boomerangDone, DISPATCH_TIME_FOREVER);
	dispatch_source_cancel(serverSource);
	mach_port_deallocate(mach_task_self(), serverPort);

	// Stash boomerang pid in environment to later be able to call waitpid on it
	char pidBuf[10];
	snprintf(pidBuf, 10, "%d", boomerangPid);
	setenv("BOOMERANG_PID", pidBuf, 1);
}

int boomerang_recoverPrimitives(bool firstRetrieval, bool shouldEndBoomerang)
{
	// Mach port to boomerang should be stored in our registeredPorts[2]
	// Use it to recover primitives, afterwards replace it with MACH_PORT_NULL to make launchd happy
	mach_port_t *registeredPorts;
	mach_msg_type_number_t registeredPortsCount = 0;
	if (mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount) != 0 || registeredPortsCount < 3) return -1;
	mach_port_t boomerangPort = registeredPorts[2];
	if (boomerangPort == MACH_PORT_NULL) return -2;
	jbclient_xpc_set_custom_port(boomerangPort);
	registeredPorts[2] = MACH_PORT_NULL;
	mach_ports_register(mach_task_self(), registeredPorts, registeredPortsCount);

	// Recover boomerang pid from environment
	pid_t boomerangPid = 0;
	const char *pidBuf = getenv("BOOMERANG_PID");
	if (pidBuf) {
		boomerangPid = atoi(pidBuf);
		unsetenv("BOOMERANG_PID");
	}

	// Retrieve primitives
	// For performance reasons we only use physrw_pte until the first userspace reboot
	// Handing off full physrw from the app is really slow and causes watchdog timeouts
	// But from launchd it's generally fine, no clue why
	bool physrwPTE = firstRetrieval && !is_kcall_available();
	jbclient_initialize_primitives_internal(physrwPTE);

	if (shouldEndBoomerang) {
		// Send done message to boomerang
		jbclient_boomerang_done();

		// Remove boomerang zombie proc if needed
		if (boomerangPid != 0) {
			int boomerangStatus;
			waitpid(boomerangPid, &boomerangStatus, WEXITED);
			waitpid(boomerangPid, &boomerangStatus, 0);
		}
	}
	
	return 0;
}
