#import <libjailbreak/libjailbreak.h>
#import "internal.h"

#import <Foundation/Foundation.h>
#import <CoreServices/LSApplicationProxy.h>

int reboot3(uint64_t flags, ...);
#define RB2_USERREBOOT (0x2000000000000000llu)
extern char **environ;

void print_usage(void)
{
	printf("Usage: jbctl <command> <arguments>\n\
Available commands:\n\
	proc_set_debugged <pid>\t\tMarks the process with the given pid as being debugged, allowing invalid code pages inside of it\n\
	trustcache info\t\t\tPrint info about all jailbreak related trustcaches and the cdhashes contained in them\n\
	trustcache clear\t\tClears all existing cdhashes from the jailbreaks trustcache\n\
	trustcache add <cdhash>\t\tAdd an arbitrary cdhash to the jailbreaks trustcache\n\
	update <tipa/basebin> <path>\tInitiates a jailbreak update either based on a TIPA or based on a basebin.tar file, TIPA installation depends on TrollStore, afterwards it triggers a userspace reboot\n");
}

int main(int argc, char* argv[])
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2) {
		print_usage();
		return 1;
	}

	if (getuid() != 0 && geteuid() == 0) {
		// When jailbroken the Dopamine app cannot have uid 0 because it can't drop it anymore without loosing it
		// So in some cases (e.g. for spawning dpkg) we need to use jbctl to get it
		setuid(0);
	}

	const char *rootPath = jbclient_get_jbroot();
	if (rootPath) {
		gSystemInfo.jailbreakInfo.rootPath = strdup(rootPath);
	}

	char *cmd = argv[1];
	if (!strcmp(cmd, "proc_set_debugged")) {
		if (argc != 3) {
			print_usage();
			return 1;
		}
		int pid = atoi(argv[2]);
		int64_t result = jbclient_platform_set_process_debugged(pid, true);
		if (result == 0) {
			printf("Successfully marked proc of pid %d as debugged\n", pid);
		}
		else {
			printf("Failed to mark proc of pid %d as debugged\n", pid);
		}
	}
	else if (!strcmp(cmd, "trustcache")) {
		if (argc < 3) {
			print_usage();
			return 2;
		}
		if (getuid() != 0) {
			printf("ERROR: trustcache subcommand requires root.\n");
			return 3;
		}
		const char *trustcacheCmd = argv[2];
		if (!strcmp(trustcacheCmd, "info")) {
			xpc_object_t tcArr = nil;
			if (jbclient_root_trustcache_info(&tcArr) == 0) {
				size_t tcCount = xpc_array_get_count(tcArr);
				for (size_t i = 0; i < tcCount; i++) {
					xpc_object_t tc = xpc_array_get_dictionary(tcArr, i);
					size_t uuidLength = 0;
					const void *uuidData = xpc_dictionary_get_data(tc, "uuid", &uuidLength);
					xpc_object_t cdhashesArr = xpc_dictionary_get_array(tc, "cdhashes");
					if (uuidData && cdhashesArr) {
						size_t length = xpc_array_get_count(cdhashesArr);
						char uuidString[uuidLength * 2 + 1];
						convert_data_to_hex_string(uuidData, uuidLength, uuidString);
						printf("Jailbreak Trustcache %zd <UUID: %s> (length: %zd)\n", i, uuidString, length);
						for (size_t j = 0; j < length; j++) {
							size_t cdhashLength = 0;
							const void *cdhashData = xpc_array_get_data(cdhashesArr, j, &cdhashLength);
							if (cdhashData) {
								char cdhashString[cdhashLength * 2 + 1];
								convert_data_to_hex_string(cdhashData, cdhashLength, cdhashString);
								printf("| %zd:\t%s\n", j+1, cdhashString);
							}
						}
					}
				}
			}
			return 0;
		}
		else if (!strcmp(trustcacheCmd, "clear")) {
			return jbclient_root_trustcache_clear();
		}
		else if (!strcmp(trustcacheCmd, "add")) {
			if (argc < 4) {
				print_usage();
				return 2;
			}
			const char *cdhashString = argv[3];
			if (strlen(cdhashString) != (sizeof(cdhash_t) * 2)) {
				printf("ERROR: passed cdhash has wrong length\n");
				return 2;
			}
			cdhash_t cdhash;
			if (convert_hex_string_to_data(cdhashString, &cdhash)) {
				printf("ERROR: passed cdhash is malformed\n");
				return 2;
			}
			return jbclient_root_trustcache_add_cdhash(cdhash, sizeof(cdhash));
		}
	}
	else if (!strcmp(cmd, "reboot_userspace")) {
		return reboot3(RB2_USERREBOOT);
	}
	else if (!strcmp(cmd, "update")) {
		if (argc < 4) {
			print_usage();
			return 2;
		}
		char *updateType = argv[2];
		char *updateFile = argv[3];
		if (access(updateFile, F_OK) != 0) {
			printf("ERROR: File %s does not exist\n", updateFile);
			return 3;
		}

		if (!strcmp(updateType, "tipa")) {
			setsid();

			LSApplicationProxy *trollstoreAppProxy = [LSApplicationProxy applicationProxyForIdentifier:@"com.opa334.TrollStore"];
			if (!trollstoreAppProxy || !trollstoreAppProxy.installed) {
				printf("Unable to locate TrollStore, doesn't seem like it's installed.\n");
				return 4;
			}
			NSString *trollstorehelperPath = [trollstoreAppProxy.bundleURL.path stringByAppendingPathComponent:@"trollstorehelper"];
			int r = exec_cmd(trollstorehelperPath.fileSystemRepresentation, "install", "skip-uicache", "force", updateFile, NULL);
			if (r != 0) {
				printf("Failed to install tipa via TrollStore: %d\n", r);
				return 5;
			}

			LSApplicationProxy *dopamineAppProxy = [LSApplicationProxy applicationProxyForIdentifier:@"com.opa334.Dopamine"];
			if (!dopamineAppProxy) {
				printf("Unable to locate newly installed Dopamine build.\n");
				return 6;
			}
			updateFile = strdup([dopamineAppProxy.bundleURL.path stringByAppendingPathComponent:@"basebin.tar"].fileSystemRepresentation);
			// Fall through to basebin installation
		}
		else if (strcmp(updateType, "basebin") != 0) {
			// If type is neither tipa nor basebin, bail out
			print_usage();
			return 2;
		}

		int64_t result = jbclient_platform_stage_jailbreak_update(updateFile);
		if (result == 0) {
			printf("Staged update for installation during the next userspace reboot, userspace rebooting now...\n");
			usleep(10000);
			return reboot3(RB2_USERREBOOT);
		}
		else {
			printf("Staging update failed with error code %lld\n", result);
			return result;
		}
	}
	else if (!strcmp(cmd, "internal")) {
		if (getuid() != 0) return -1;
		if (argc < 3) return -1;

		const char *internalCmd = argv[2];
		return jbctl_handle_internal(internalCmd, argc-2, &argv[2]);
	}

	return 0;
}
