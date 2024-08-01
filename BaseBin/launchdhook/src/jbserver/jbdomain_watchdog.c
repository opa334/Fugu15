#include "jbserver_global.h"

#include <stdio.h>
#include <time.h>
#include <libjailbreak/util.h>
#include "../crashreporter.h"

static bool watchdog_domain_allowed(audit_token_t clientToken)
{
	xpc_object_t entitlementValue = xpc_copy_entitlement_for_token("com.apple.private.iowatchdog.user-access", &clientToken);
	if (entitlementValue && xpc_get_type(entitlementValue) == XPC_TYPE_BOOL) {
		return xpc_bool_get_value(entitlementValue);
	}
	return false;
}

static int watchdog_intercept_userspace_panic(const char *panicMessage)
{
	FILE *outFile = crashreporter_open_outfile("userspace-panic", NULL);
	if (outFile) {
		fprintf(outFile, "\n%s", panicMessage);
		fprintf(outFile, "\n\nThis panic was prevented by Dopamine and a userspace reboot was done instead.");
		crashreporter_save_outfile(outFile);
	}

	setenv("WATCHDOG_PANIC_MESSAGE", panicMessage, 1);
	FILE *touchFile = fopen(JBROOT_PATH("/basebin/.safe_mode"), "w");
	fclose(touchFile);

	return 0;
}

static int watchdog_get_last_userspace_panic(char **panicMessage)
{
	char *messageInEnv = getenv("WATCHDOG_PANIC_MESSAGE");
	if (messageInEnv) {
		*panicMessage = strdup(messageInEnv);
		unsetenv("WATCHDOG_PANIC_MESSAGE");
		return 0;
	}
	else {
		*panicMessage = NULL;
		return 1;
	}
}

struct jbserver_domain gWatchdogDomain = {
	.permissionHandler = watchdog_domain_allowed,
	.actions = {
		// JBS_WATCHDOG_INTERCEPT_USERSPACE_PANIC
		{
			.handler = watchdog_intercept_userspace_panic,
			.args = (jbserver_arg[]){
				{ .name = "panic-message", .type = JBS_TYPE_STRING, .out = false },
				{ 0 },
			},
		},
		// JBS_WATCHDOG_GET_LAST_USERSPACE_PANIC
		{
			.handler = watchdog_get_last_userspace_panic,
			.args = (jbserver_arg[]){
				{ .name = "panic-message", .type = JBS_TYPE_STRING, .out = true },
				{ 0 },
			},
		},
		{ 0 },
	},
};