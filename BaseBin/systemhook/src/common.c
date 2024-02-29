#include "common.h"
#include <xpc/xpc.h>
#include "launchd.h"
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sandbox.h>
#include <paths.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include "envbuf.h"
#include <libjailbreak/jbclient_xpc.h>
#include <os/log.h>

#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t * __restrict, int * __restrict) __API_AVAILABLE(macos(10.8), ios(6.0));

char *JB_BootUUID = NULL;
char *JB_RootPath = NULL;

#define JBD_MSG_SETUID_FIX 21
#define JBD_MSG_PROCESS_BINARY 22
#define JBD_MSG_DEBUG_ME 24
#define JBD_MSG_FORK_FIX 25
#define JBD_MSG_INTERCEPT_USERSPACE_PANIC 26

#define JETSAM_MULTIPLIER 3
#define XPC_TIMEOUT 0.1 * NSEC_PER_SEC

#define POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE 0x48
#define POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE 0x4C
#define POSIX_SPAWNATTR_OFF_LAUNCH_TYPE 0xA8

bool stringStartsWith(const char *str, const char* prefix)
{
	if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

bool stringEndsWith(const char* str, const char* suffix)
{
	if (!str || !suffix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len) {
		return false;
	}

	return !strcmp(str + str_len - suffix_len, suffix);
}

extern char **environ;
kern_return_t bootstrap_look_up(mach_port_t port, const char *service, mach_port_t *server_port);

// Derived from posix_spawnp in Apple libc
int resolvePath(const char *file, const char *searchPath, int (^attemptHandler)(char *path))
{
	const char *env_path;
	char *bp;
	char *cur;
	char *p;
	char **memp;
	int lp;
	int ln;
	int cnt;
	int err = 0;
	int eacces = 0;
	struct stat sb;
	char path_buf[PATH_MAX];

	env_path = searchPath;
	if (!env_path) {
		env_path = getenv("PATH");
		if (!env_path) {
			env_path = _PATH_DEFPATH;
		}
	}

	/* If it's an absolute or relative path name, it's easy. */
	if (index(file, '/')) {
		bp = (char *)file;
		cur = NULL;
		goto retry;
	}
	bp = path_buf;

	/* If it's an empty path name, fail in the usual POSIX way. */
	if (*file == '\0')
		return (ENOENT);

	if ((cur = alloca(strlen(env_path) + 1)) == NULL)
		return ENOMEM;
	strcpy(cur, env_path);
	while ((p = strsep(&cur, ":")) != NULL) {
		/*
		 * It's a SHELL path -- double, leading and trailing colons
		 * mean the current directory.
		 */
		if (*p == '\0') {
			p = ".";
			lp = 1;
		} else {
			lp = strlen(p);
		}
		ln = strlen(file);

		/*
		 * If the path is too long complain.  This is a possible
		 * security issue; given a way to make the path too long
		 * the user may spawn the wrong program.
		 */
		if (lp + ln + 2 > sizeof(path_buf)) {
			err = ENAMETOOLONG;
			goto done;
		}
		bcopy(p, path_buf, lp);
		path_buf[lp] = '/';
		bcopy(file, path_buf + lp + 1, ln);
		path_buf[lp + ln + 1] = '\0';

retry:		err = attemptHandler(bp);
		switch (err) {
		case E2BIG:
		case ENOMEM:
		case ETXTBSY:
			goto done;
		case ELOOP:
		case ENAMETOOLONG:
		case ENOENT:
		case ENOTDIR:
			break;
		case ENOEXEC:
			goto done;
		default:
			/*
			 * EACCES may be for an inaccessible directory or
			 * a non-executable file.  Call stat() to decide
			 * which.  This also handles ambiguities for EFAULT
			 * and EIO, and undocumented errors like ESTALE.
			 * We hope that the race for a stat() is unimportant.
			 */
			if (stat(bp, &sb) != 0)
				break;
			if (err == EACCES) {
				eacces = 1;
				continue;
			}
			goto done;
		}
	}
	if (eacces)
		err = EACCES;
	else
		err = ENOENT;
done:
	return (err);
}

void enumeratePathString(const char *pathsString, void (^enumBlock)(const char *pathString, bool *stop))
{
	char *pathsCopy = strdup(pathsString);
	char *pathString = strtok(pathsCopy, ":");
	while (pathString != NULL) {
		bool stop = false;
		enumBlock(pathString, &stop);
		if (stop) break;
		pathString = strtok(NULL, ":");
	}
	free(pathsCopy);
}

typedef enum 
{
	kBinaryConfigDontInject = 1 << 0,
	kBinaryConfigDontProcess = 1 << 1
} kBinaryConfig;

kBinaryConfig configForBinary(const char* path, char *const argv[restrict])
{
	if (!strcmp(path, "/usr/libexec/xpcproxy")) {
		if (argv) {
			if (argv[0]) {
				if (argv[1]) {
					if (!strcmp(argv[1], "com.apple.ReportCrash")) {
						// Skip ReportCrash too as it might need to execute while jailbreakd is in a crashed state
						return (kBinaryConfigDontInject | kBinaryConfigDontProcess);
					}
					else if (!strcmp(argv[1], "com.apple.ReportMemoryException")) {
						// Skip ReportMemoryException too as it might need to execute while jailbreakd is in a crashed state
						return (kBinaryConfigDontInject | kBinaryConfigDontProcess);
					}
					else if (!strcmp(argv[1], "com.apple.logd")   ||
							 !strcmp(argv[1], "com.apple.notifyd") ||
							 !strcmp(argv[1], "com.apple.mobile.usermanagerd")) {
						// These seem to be problematic on iOS 16+ (dyld gets stuck in a weird way)
						if (__builtin_available(iOS 16.0, *)) {
							return (kBinaryConfigDontInject | kBinaryConfigDontProcess);
						}
					}
					else if (stringStartsWith(argv[1], "com.apple.WebKit.WebContent")) {
						// The most sandboxed process on the system, we can't support it on iOS 16+ for now
						if (__builtin_available(iOS 16.0, *)) {
							return (kBinaryConfigDontInject | kBinaryConfigDontProcess);
						}
					}
#ifndef __arm64e__
 					// Attempt to solve issues with VPN on arm64
					else if (!strcmp(argv[1], "com.apple.terminusd") ||
							 !strcmp(argv[1], "com.apple.nesessionmanager")) {
						return (kBinaryConfigDontInject | kBinaryConfigDontProcess);
					}
#endif
				}
			}
		}
	}

	// Blacklist to ensure general system stability
	// I don't like this but for some processes it seems neccessary
	const char *processBlacklist[] = {
		"/System/Library/Frameworks/GSS.framework/Helpers/GSSCred",
		"/System/Library/PrivateFrameworks/DataAccess.framework/Support/dataaccessd",
		"/System/Library/PrivateFrameworks/IDSBlastDoorSupport.framework/XPCServices/IDSBlastDoorService.xpc/IDSBlastDoorService",
		"/System/Library/PrivateFrameworks/MessagesBlastDoorSupport.framework/XPCServices/MessagesBlastDoorService.xpc/MessagesBlastDoorService",
	};
	size_t blacklistCount = sizeof(processBlacklist) / sizeof(processBlacklist[0]);
	for (size_t i = 0; i < blacklistCount; i++)
	{
		if (!strcmp(processBlacklist[i], path)) return (kBinaryConfigDontInject | kBinaryConfigDontProcess);
	}

	return 0;
}

// 1. Make sure the about to be spawned binary and all of it's dependencies are trust cached
// 2. Insert "DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib" into all binaries spawned

int spawn_hook_common(pid_t *restrict pid, const char *restrict path,
					   const posix_spawn_file_actions_t *restrict file_actions,
					   const posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict],
					   void *orig,
					   int (*trust_binary)(const char *),
					   int (*set_process_debugged)(uint64_t pid, bool fullyDebugged))
{
	int (*pspawn_orig)(pid_t *restrict, const char *restrict, const posix_spawn_file_actions_t *restrict, const posix_spawnattr_t *restrict, char *const[restrict], char *const[restrict]) = orig;
	if (!path) {
		return pspawn_orig(pid, path, file_actions, attrp, argv, envp);
	}

	kBinaryConfig binaryConfig = configForBinary(path, argv);

	if (!(binaryConfig & kBinaryConfigDontProcess)) {
		// jailbreakd: Upload binary to trustcache if needed
		trust_binary(path);
	}

	const char *existingLibraryInserts = envbuf_getenv((const char **)envp, "DYLD_INSERT_LIBRARIES");
	__block bool systemHookAlreadyInserted = false;
	if (existingLibraryInserts) {
		enumeratePathString(existingLibraryInserts, ^(const char *existingLibraryInsert, bool *stop) {
			if (!strcmp(existingLibraryInsert, HOOK_DYLIB_PATH)) {
				systemHookAlreadyInserted = true;
			}
			else {
				trust_binary(existingLibraryInsert);
			}
		});
	}

	int JBEnvAlreadyInsertedCount = (int)systemHookAlreadyInserted;

	// Check if we can find at least one reason to not insert jailbreak related environment variables
	// In this case we also need to remove pre existing environment variables if they are already set
	bool shouldInsertJBEnv = true;
	bool hasSafeModeVariable = false;
	do {
		if (binaryConfig & kBinaryConfigDontInject) {
			shouldInsertJBEnv = false;
			break;
		}

		// Check if we can find a _SafeMode or _MSSafeMode variable
		// In this case we do not want to inject anything
		const char *safeModeValue = envbuf_getenv((const char **)envp, "_SafeMode");
		const char *msSafeModeValue = envbuf_getenv((const char **)envp, "_MSSafeMode");
		if (safeModeValue) {
			if (!strcmp(safeModeValue, "1")) {
				shouldInsertJBEnv = false;
				hasSafeModeVariable = true;
				break;
			}
		}
		if (msSafeModeValue) {
			if (!strcmp(msSafeModeValue, "1")) {
				shouldInsertJBEnv = false;
				hasSafeModeVariable = true;
				break;
			}
		}

		if (attrp) {
			int proctype = 0;
			posix_spawnattr_getprocesstype_np(attrp, &proctype);
			if (proctype == POSIX_SPAWN_PROC_TYPE_DRIVER) {
				// Do not inject hook into DriverKit drivers
				shouldInsertJBEnv = false;
				break;
			}
		}

		if (access(HOOK_DYLIB_PATH, F_OK) != 0) {
			// If the hook dylib doesn't exist, don't try to inject it (would crash the process)
			shouldInsertJBEnv = false;
			break;
		}
	} while (0);

	// If systemhook is being injected and Jetsam limits are set, increase them by a factor of JETSAM_MULTIPLIER
	if (shouldInsertJBEnv) {
		if (attrp) {
			uint8_t *attrStruct = *attrp;
			if (attrStruct) {
				int memlimit_active = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE);
				if (memlimit_active != -1) {
					*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE) = memlimit_active * JETSAM_MULTIPLIER;
				}
				int memlimit_inactive = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE);
				if (memlimit_inactive != -1) {
					*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE) = memlimit_inactive * JETSAM_MULTIPLIER;
				}

				// On iOS 16, disable launch constraints
				// Not working, doesn't seem feasable
				/*if (__builtin_available(iOS 16.0, *)) {
					uint32_t bufsize = PATH_MAX;
					char executablePath[PATH_MAX];
					_NSGetExecutablePath(executablePath, &bufsize);
					// We could do the following here
					// posix_spawnattr_set_launch_type_np(*attrp, 0);
					// But I don't know how to get the compiler to weak link it
					// So we just set it by offset
					if (getpid() == 1) {
						FILE *f = fopen("/var/mobile/launch_type.txt", "a");
						const char *toLog = path;
						if (!strcmp(path, "/usr/libexec/xpcproxy") && argv) {
							if (argv[0]) {
								if (argv[1]) {
									toLog = argv[1];
								}
							}
						}
						fprintf(f, "%s has launch type %u\n", toLog, *(uint8_t *)(attrStruct + POSIX_SPAWNATTR_OFF_LAUNCH_TYPE));
						fclose(f);
					}
					else if (!strcmp(executablePath, "/usr/libexec/xpcproxy")) {
						FILE *f = fopen("/tmp/launch_type_xpcproxy.txt", "a");
						if (f) {
							fprintf(f, "%s has launch type %u\n", path, *(uint8_t *)(attrStruct + POSIX_SPAWNATTR_OFF_LAUNCH_TYPE));
							fclose(f);
						}
					}
					else {
						os_log(OS_LOG_DEFAULT, "systemhook %{public}s has launch type %u\n", path, *(uint8_t *)(attrStruct + POSIX_SPAWNATTR_OFF_LAUNCH_TYPE));
					}*/
					
					//*(uint8_t *)(attrStruct + POSIX_SPAWNATTR_OFF_LAUNCH_TYPE) = ...
					/*if (!strcmp(path, "/usr/libexec/xpcproxy") && argv) {
						if (argv[0]) {
							if (argv[1]) {
								if (stringStartsWith(argv[1], "com.apple.WebKit.WebContent.")) {
									*(uint8_t *)(attrStruct + POSIX_SPAWNATTR_OFF_LAUNCH_TYPE) = 0;
								}
							}
						}
					}
				}*/
			}
		}
	}

	int retval = -1;

	if ((shouldInsertJBEnv && JBEnvAlreadyInsertedCount == 1) || (!shouldInsertJBEnv && JBEnvAlreadyInsertedCount == 0 && !hasSafeModeVariable)) {
		// we're already good, just call orig
		retval = pspawn_orig(pid, path, file_actions, attrp, argv, envp);
	}
	else {
		// the state we want to be in is not the state we are in right now

		char **envc = envbuf_mutcopy((const char **)envp);

		if (shouldInsertJBEnv) {
			if (!systemHookAlreadyInserted) {
				char newLibraryInsert[strlen(HOOK_DYLIB_PATH) + (existingLibraryInserts ? (strlen(existingLibraryInserts) + 1) : 0) + 1];
				strcpy(newLibraryInsert, HOOK_DYLIB_PATH);
				if (existingLibraryInserts) {
					strcat(newLibraryInsert, ":");
					strcat(newLibraryInsert, existingLibraryInserts);
				}
				envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newLibraryInsert);
			}
		}
		else {
			if (systemHookAlreadyInserted && existingLibraryInserts) {
				if (!strcmp(existingLibraryInserts, HOOK_DYLIB_PATH)) {
					envbuf_unsetenv(&envc, "DYLD_INSERT_LIBRARIES");
				}
				else {
					char *newLibraryInsert = malloc(strlen(existingLibraryInserts)+1);
					newLibraryInsert[0] = '\0';

					__block bool first = true;
					enumeratePathString(existingLibraryInserts, ^(const char *existingLibraryInsert, bool *stop) {
						if (strcmp(existingLibraryInsert, HOOK_DYLIB_PATH) != 0) {
							if (first) {
								strcpy(newLibraryInsert, existingLibraryInsert);
								first = false;
							}
							else {
								strcat(newLibraryInsert, ":");
								strcat(newLibraryInsert, existingLibraryInsert);
							}
						}
					});
					envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newLibraryInsert);

					free(newLibraryInsert);
				}
			}
			envbuf_unsetenv(&envc, "_SafeMode");
			envbuf_unsetenv(&envc, "_MSSafeMode");
		}

		retval = pspawn_orig(pid, path, file_actions, attrp, argv, envc);
		envbuf_free(envc);
	}

	if (retval == 0 && attrp != NULL && pid != NULL) {
		short flags = 0;
		if (posix_spawnattr_getflags(attrp, &flags) == 0) {
			if (flags & POSIX_SPAWN_START_SUSPENDED) {
				// If something spawns a process as suspended, ensure mapping invalid pages in it is possible
				// Normally it would only be possible after systemhook.dylib enables it
				// Fixes Frida issues
				int r = set_process_debugged(*pid, false);
			}
		}
	}

	return retval;
}
