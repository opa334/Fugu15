#include "jbserver_global.h"

#include <libjailbreak/codesign.h>
#include <libjailbreak/libjailbreak.h>

static bool platform_domain_allowed(audit_token_t clientToken)
{
	pid_t pid = audit_token_to_pid(clientToken);
	uint32_t csflags = 0;
	if (csops_audittoken(pid, CS_OPS_STATUS, &csflags, sizeof(csflags), &clientToken) != 0) return false;
	return (csflags & CS_PLATFORM_BINARY);
}

int platform_set_process_debugged(uint64_t pid, bool fullyDebugged)
{
	uint64_t proc = proc_find(pid);
	if (!proc) return -1;
	cs_allow_invalid(proc, fullyDebugged);
	return 0;
}

static int platform_stage_jailbreak_update(const char *updateTar)
{
	if (!access(updateTar, F_OK)) {
		setenv("STAGED_JAILBREAK_UPDATE", updateTar, 1);
		return 0;
	}
	return 1;
}

static int platform_jbsettings_get(const char *key, xpc_object_t *valueOut)
{
	if (!strcmp(key, "markAppsAsDebugged")) {
		*valueOut = xpc_bool_create(jbsetting(markAppsAsDebugged));
		return 0;
	}
	return -1;
}

static int platform_jbsettings_set(const char *key, xpc_object_t value)
{
	if (!strcmp(key, "markAppsAsDebugged") && xpc_get_type(value) == XPC_TYPE_BOOL) {
		gSystemInfo.jailbreakSettings.markAppsAsDebugged = xpc_bool_get_value(value);
		return 0;
	}
	return -1;
}

struct jbserver_domain gPlatformDomain = {
	.permissionHandler = platform_domain_allowed,
	.actions = {
		// JBS_PLATFORM_SET_PROCESS_DEBUGGED
		{
			.handler = platform_set_process_debugged,
			.args = (jbserver_arg[]){
				{ .name = "pid", .type = JBS_TYPE_UINT64, .out = false },
				{ .name = "fully-debugged", .type = JBS_TYPE_BOOL, .out = false },
				{ 0 },
			},
		},
		// JBS_PLATFORM_STAGE_JAILBREAK_UPDATE
		{
			.handler = platform_stage_jailbreak_update,
			.args = (jbserver_arg[]){
				{ .name = "update-tar", .type = JBS_TYPE_STRING, .out = false },
				{ 0 },
			},
		},
		// JBS_PLATFORM_JBSETTINGS_GET
		{
			.handler = platform_jbsettings_get,
			.args = (jbserver_arg[]){
				{ .name = "key", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "value", .type = JBS_TYPE_XPC_GENERIC, .out = true },
			},
		},
		// JBS_PLATFORM_JBSETTINGS_SET
		{
			.handler = platform_jbsettings_set,
			.args = (jbserver_arg[]){
				{ .name = "key", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "value", .type = JBS_TYPE_XPC_GENERIC, .out = false },
			},
		},
		{ 0 },
	},
};