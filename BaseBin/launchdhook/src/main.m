#import <Foundation/Foundation.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/util.h>
#import <libjailbreak/kernel.h>
#import <mach-o/dyld.h>
#import <spawn.h>
#import <substrate.h>

#import "spawn_hook.h"
#import "xpc_hook.h"
#import "daemon_hook.h"
#import "ipc_hook.h"
#import "dsc_hook.h"
#import "jetsam_hook.h"
#import "crashreporter.h"
#import "boomerang.h"
#import "update.h"

bool gInEarlyBoot = true;

void abort_with_reason(uint32_t reason_namespace, uint64_t reason_code, const char *reason_string, uint64_t reason_flags);

__attribute__((constructor)) static void initializer(void)
{
	crashreporter_start();

	// If we performed a jbupdate before the userspace reboot, these vars will be set
	// In that case, we want to run finalizers
	const char *jbupdatePrevVersion = getenv("JBUPDATE_PREV_VERSION");
	const char *jbupdateNewVersion = getenv("JBUPDATE_NEW_VERSION");
	if (jbupdatePrevVersion && jbupdateNewVersion) {
		jbupdate_finalize_stage1(jbupdatePrevVersion, jbupdateNewVersion);
	}

	bool firstLoad = false;
	if (getenv("DOPAMINE_INITIALIZED") != 0) {
		// If Dopamine was initialized before, we assume we're coming from a userspace reboot

		// Stock bug: These prefs wipe themselves after a reboot (they contain a boot time and this is matched when they're loaded)
		// But on userspace reboots, they apparently do not get wiped as boot time doesn't change
		// We could try to change the boot time ourselves, but I'm worried of potential side effects
		// So we just wipe the offending preferences ourselves
		// In practice this fixes nano launch daemons not being loaded after the userspace reboot, resulting in certain apple watch features breaking
		if (!access("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRRootCommander.volatile.plist", W_OK)) {
			remove("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRRootCommander.volatile.plist");
		}
		if (!access("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRLaunchNotificationController.volatile.plist", W_OK)) {
			remove("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRLaunchNotificationController.volatile.plist");
		}
	}
	else {
		// Here we should have been injected into a live launchd on the fly
		// In this case, we are not in early boot...
		gInEarlyBoot = false;
		firstLoad = true;
	}

	int err = boomerang_recoverPrimitives(firstLoad, true);
	if (err != 0) {
		char msg[1000];
		snprintf(msg, 1000, "Dopamine: Failed to recover primitives (error %d), cannot continue.", err);
		abort_with_reason(7, 1, msg, 0);
		return;
	}

	if (jbupdatePrevVersion && jbupdateNewVersion) {
		jbupdate_finalize_stage2(jbupdatePrevVersion, jbupdateNewVersion);
		unsetenv("JBUPDATE_PREV_VERSION");
		unsetenv("JBUPDATE_NEW_VERSION");
	}

	cs_allow_invalid(proc_self(), false);

	initXPCHooks();
	initDaemonHooks();
	initSpawnHooks();
	initIPCHooks();
	initDSCHooks();
	initJetsamHook();

	// This will ensure launchdhook is always reinjected after userspace reboots
	// As this launchd will pass environ to the next launchd...
	setenv("DYLD_INSERT_LIBRARIES", JBRootPath("/basebin/launchdhook.dylib"), 1);

	// Mark Dopamine as having been initialized before
	setenv("DOPAMINE_INITIALIZED", "1", 1);

	// Set an identifier that uniquely identifies this userspace boot
	// Part of rootless v2 spec
	setenv("LAUNCHD_UUID", [NSUUID UUID].UUIDString.UTF8String, 1);
}