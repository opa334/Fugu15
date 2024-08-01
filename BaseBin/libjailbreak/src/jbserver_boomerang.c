#include "jbserver_boomerang.h"
#include "info.h"
#include "kernel.h"
#include "util.h"
#include "primitives.h"
#include "physrw.h"
#include "physrw_pte.h"
#include <bsm/audit.h>

// Implements JBS_DOMAIN_ROOT, but only the functionality required for boomerang
// Exports symbols so that the logic can be reused by launchdhook

static bool boomerang_domain_allowed(audit_token_t clientToken)
{
	// This server is both used from launchd to boomerang and boomerang back to launchd
	// Ensure one of the participants in this communication is launchd
	return (audit_token_to_pid(clientToken) == 1) || (getpid() == 1);
}

int boomerang_get_physrw(audit_token_t *clientToken, bool singlePTE, uint64_t *singlePTEAsidPtr)
{
	int r = -1;
	pid_t pid = audit_token_to_pid(*clientToken);

	thread_caffeinate_start();
	if (singlePTE) {
		r = physrw_pte_handoff(pid, singlePTEAsidPtr);
	}
	else {
		r = physrw_handoff(pid);
	}
	thread_caffeinate_stop();

	return r;
}

int boomerang_sign_thread(audit_token_t *clientToken, mach_port_t threadPort)
{
	pid_t pid = audit_token_to_pid(*clientToken);
	uint64_t proc = proc_find(pid);
	if (proc) {
		int r = sign_kernel_thread(proc, threadPort);
		proc_rele(proc);
		return r;
	}
	return -1;
}

int boomerang_get_sysinfo(xpc_object_t *sysInfoOut)
{
	xpc_object_t sysInfo = xpc_dictionary_create_empty();
	SYSTEM_INFO_SERIALIZE(sysInfo);
	*sysInfoOut = sysInfo;
	return 0;
}

struct jbserver_domain gUnusedDomain = {
	.permissionHandler = NULL,
	.actions = {
		{ 0 },
	},
};

struct jbserver_domain gBoomerangDomain = {
	.permissionHandler = boomerang_domain_allowed,
	.actions = {
		// JBS_ROOT_GET_PHYSRW
		{
			.handler = boomerang_get_physrw,
			.args = (jbserver_arg[]){
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ .name = "single-pte", .type = JBS_TYPE_BOOL, .out = false },
				{ .name = "single-pte-asid-ptr", .type = JBS_TYPE_UINT64, .out = true },
				{ 0 },
			},
		},
		// JBS_ROOT_SIGN_THREAD
		{
			.handler = boomerang_sign_thread,
			.args = (jbserver_arg[]){
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ .name = "thread-port", .type = JBS_TYPE_UINT64, .out = false },
				{ 0 },
			},
		},
		// JBS_ROOT_GET_SYSINFO
		{
			.handler = boomerang_get_sysinfo,
			.args = (jbserver_arg[]){
				{ .name = "sysinfo", .type = JBS_TYPE_DICTIONARY, .out = true },
				{ 0 },
			},
		},
		{ 0 },
	},
};

struct jbserver_impl gBoomerangServer = {
	.maxDomain = 1,
	.domains = (struct jbserver_domain*[]){
		&gUnusedDomain,
		&gUnusedDomain,
		&gUnusedDomain,
		&gBoomerangDomain,
		NULL,
	}
};

int jbserver_received_boomerang_xpc_message(struct jbserver_impl *server, xpc_object_t xmsg)
{
	int r = jbserver_received_xpc_message(server, xmsg);
	if (r != 0) {
		uint64_t action = xpc_dictionary_get_uint64(xmsg, "action");
		if (action == JBS_BOOMERANG_DONE) {
			xpc_object_t xreply = xpc_dictionary_create_reply(xmsg);
			xpc_dictionary_set_uint64(xreply, "result", 0);
			xpc_pipe_routine_reply(xreply);
			xpc_release(xreply);
			return JBS_BOOMERANG_DONE;
		}
	}
	return r;
}
