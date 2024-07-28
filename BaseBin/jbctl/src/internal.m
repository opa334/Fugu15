#import "internal.h"
#import "dyldpatch.h"
#import "codesign.h"
#import <libjailbreak/carboncopy.h>
#import <Foundation/Foundation.h>
#import <libjailbreak/libjailbreak.h>
#import <sys/mount.h>

SInt32 CFUserNotificationDisplayAlert(CFTimeInterval timeout, CFOptionFlags flags, CFURLRef iconURL, CFURLRef soundURL, CFURLRef localizationURL, CFStringRef alertHeader, CFStringRef alertMessage, CFStringRef defaultButtonTitle, CFStringRef alternateButtonTitle, CFStringRef otherButtonTitle, CFOptionFlags *responseFlags) API_AVAILABLE(ios(3.0));

void execute_unsandboxed(void (^block)(void))
{
	uint64_t credBackup = 0;
	jbclient_root_steal_ucred(0, &credBackup);
	block();
	jbclient_root_steal_ucred(credBackup, NULL);
}

int mount_unsandboxed(const char *type, const char *dir, int flags, void *data)
{
	__block int r = 0;
	execute_unsandboxed(^{
		r = mount(type, dir, flags, data);
	});
	return r;
}

void ensureProtected(const char *path)
{
	struct statfs sb;
	statfs(path, &sb);
	if (strcmp(path, sb.f_mntonname) != 0) {
		mount_unsandboxed("bindfs", path, 0, (void *)path);
	}
}

void ensureProtectionActive(void)
{
	// Protect /private/preboot/UUID/<System, usr> from being modified by bind mounting them on top of themselves
	// This protects dumb users from accidentally deleting these, which would induce a recovery loop after rebooting
	ensureProtected(prebootUUIDPath("/System"));
	ensureProtected(prebootUUIDPath("/usr"));
}

int jbctl_handle_internal(const char *command, int argc, char* argv[])
{
	if (!strcmp(command, "launchd_stash_port")) {
		mach_port_t *selfInitPorts = NULL;
		mach_msg_type_number_t selfInitPortsCount = 0;
		if (mach_ports_lookup(mach_task_self(), &selfInitPorts, &selfInitPortsCount) != 0) {
			printf("ERROR: Failed port lookup on self\n");
			return -1;
		}
		if (selfInitPortsCount < 3) {
			printf("ERROR: Unexpected initports count on self\n");
			return -1;
		}
		if (selfInitPorts[2] == MACH_PORT_NULL) {
			printf("ERROR: Port to stash not set\n");
			return -1;
		}

		printf("Port to stash: %u\n", selfInitPorts[2]);

		mach_port_t launchdTaskPort;
		if (task_for_pid(mach_task_self(), 1, &launchdTaskPort) != 0) {
			printf("task_for_pid on launchd failed\n");
			return -1;
		}
		mach_port_t *launchdInitPorts = NULL;
		mach_msg_type_number_t launchdInitPortsCount = 0;
		if (mach_ports_lookup(launchdTaskPort, &launchdInitPorts, &launchdInitPortsCount) != 0) {
			printf("mach_ports_lookup on launchd failed\n");
			return -1;
		}
		if (launchdInitPortsCount < 3) {
			printf("ERROR: Unexpected initports count on launchd\n");
			return -1;
		}
		launchdInitPorts[2] = selfInitPorts[2]; // Transfer port to launchd
		if (mach_ports_register(launchdTaskPort, launchdInitPorts, launchdInitPortsCount) != 0) {
			printf("ERROR: Failed stashing port into launchd\n");
			return -1;
		}
		mach_port_deallocate(mach_task_self(), launchdTaskPort);
		return 0;
	}
	else if (!strcmp(command, "protection_init")) {
		ensureProtectionActive();
		return 0;
	}
	else if (!strcmp(command, "fakelib_init")) {
		NSString *basebinPath = JBROOT_PATH(@"/basebin");
		NSString *fakelibPath = JBROOT_PATH(@"/basebin/.fakelib");
		printf("Initalizing fakelib...\n");

		// Copy /usr/lib to /var/jb/basebin/.fakelib
		[[NSFileManager defaultManager] removeItemAtPath:fakelibPath error:nil];
		[[NSFileManager defaultManager] createDirectoryAtPath:fakelibPath withIntermediateDirectories:YES attributes:nil error:nil];
		carbonCopy(@"/usr/lib", fakelibPath);

		// Backup and patch dyld
		NSString *dyldBackupPath = JBROOT_PATH(@"/basebin/.dyld.orig");
		NSString *dyldPatchPath = JBROOT_PATH(@"/basebin/.dyld.patched");
		carbonCopy(@"/usr/lib/dyld", dyldBackupPath);
		carbonCopy(@"/usr/lib/dyld", dyldPatchPath);
		apply_dyld_patch(dyldPatchPath.fileSystemRepresentation);
		resign_file(dyldPatchPath, YES);

		// Copy systemhook to fakelib
		carbonCopy(JBROOT_PATH(@"/basebin/systemhook.dylib"), JBROOT_PATH(@"/basebin/.fakelib/systemhook.dylib"));

		// Replace dyld in fakelib with patched dyld
		NSString *fakelibDyldPath = [fakelibPath stringByAppendingPathComponent:@"dyld"];
		[[NSFileManager defaultManager] removeItemAtPath:fakelibDyldPath error:nil];
		carbonCopy(dyldPatchPath, JBROOT_PATH(@"/basebin/.fakelib/dyld"));
		return 0;
	}
	else if (!strcmp(command, "fakelib_mount")) {
		printf("Applying mount...\n");
		return mount_unsandboxed("bindfs", "/usr/lib", MNT_RDONLY, (void *)JBROOT_PATH("/basebin/.fakelib"));
	}
	else if (!strcmp(command, "startup")) {
		ensureProtectionActive();
		char *panicMessage = NULL;
		if (jbclient_watchdog_get_last_userspace_panic(&panicMessage) == 0) {
			NSString *printMessage = [NSString stringWithFormat:@"Dopamine has protected you from a userspace panic by temporarily disabling tweak injection and triggering a userspace reboot instead. A log is available under Analytics in the Preferences app. You can reenable tweak injection in the Dopamine app.\n\nPanic message: \n%s", panicMessage];
			CFUserNotificationDisplayAlert(0, 2/*kCFUserNotificationCautionAlertLevel*/, NULL, NULL, NULL, CFSTR("Watchdog Timeout"), (__bridge CFStringRef)printMessage, NULL, NULL, NULL, NULL);
			free(panicMessage);
		}
		exec_cmd(JBROOT_PATH("/usr/bin/uicache"), "-a", NULL);
	}
	else if (!strcmp(command, "install_pkg")) {
		if (argc > 1) {
			extern char **environ;
			char *dpkg = JBROOT_PATH("/usr/bin/dpkg");
			int r = execve(dpkg, (char *const *)(const char *[]){dpkg, "-i", argv[1], NULL}, environ);
			return r;
		}
		return -1;
	}
	return -1;
}
