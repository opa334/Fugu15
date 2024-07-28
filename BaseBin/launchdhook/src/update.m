#include <stdlib.h>
#include <libjailbreak/util.h>
#include <libjailbreak/trustcache.h>
#include <libjailbreak/kcall_arm64.h>
#include <xpc/xpc.h>
#include <dlfcn.h>

#import <Foundation/Foundation.h>

void abort_with_reason(uint32_t reason_namespace, uint64_t reason_code, const char *reason_string, uint64_t reason_flags);

int jbupdate_basebin(const char *basebinTarPath)
{
	@autoreleasepool {
		int r = 0;
		if (access(basebinTarPath, F_OK) != 0) return 1;

		NSString *prevVersion = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/basebin/.version") encoding:NSUTF8StringEncoding error:nil] ?: @"2.0";

		// Extract basebin tar
		NSString *tmpExtractionPath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
		r = libarchive_unarchive(basebinTarPath, tmpExtractionPath.fileSystemRepresentation);
		if (r != 0) {
			[[NSFileManager defaultManager] removeItemAtPath:tmpExtractionPath error:nil];
			return 2;
		}
		NSString *tmpBasebinPath = [tmpExtractionPath stringByAppendingPathComponent:@"basebin"];

		// Update basebin trustcache
		NSString *trustcachePath = [tmpBasebinPath stringByAppendingPathComponent:@"basebin.tc"];
		if (![[NSFileManager defaultManager] fileExistsAtPath:trustcachePath]) return 3;
		trustcache_file_v1 *basebinTcFile = NULL;
		if (trustcache_file_build_from_path(trustcachePath.fileSystemRepresentation, &basebinTcFile) != 0) {
			[[NSFileManager defaultManager] removeItemAtPath:tmpExtractionPath error:nil];
			return 4;
		}
		r = trustcache_file_upload_with_uuid(basebinTcFile, BASEBIN_TRUSTCACHE_UUID);
		free(basebinTcFile);
		if (r != 0) {
			[[NSFileManager defaultManager] removeItemAtPath:tmpExtractionPath error:nil];
			return 5;
		}
		else {
			[[NSFileManager defaultManager] removeItemAtPath:trustcachePath error:nil];
		}

		// Replace basebin content
		NSArray *newBasebinContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:tmpBasebinPath error:nil];
		for (NSString *basebinItem in newBasebinContents) {
			NSString *newBasebinPath = [tmpBasebinPath stringByAppendingPathComponent:basebinItem];
			NSString *oldBasebinPath = [JBROOT_PATH(@"/basebin") stringByAppendingPathComponent:basebinItem];
			if ([[NSFileManager defaultManager] fileExistsAtPath:oldBasebinPath]) {
				[[NSFileManager defaultManager] removeItemAtPath:oldBasebinPath error:nil];
			}
			[[NSFileManager defaultManager] copyItemAtPath:newBasebinPath toPath:oldBasebinPath error:nil];
		}
		[[NSFileManager defaultManager] removeItemAtPath:tmpExtractionPath error:nil];

		// Update systemhook in fakelib
		[[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/basebin/.fakelib/systemhook.dylib") error:nil];
		[[NSFileManager defaultManager] copyItemAtPath:JBROOT_PATH(@"/basebin/systemhook.dylib") toPath:JBROOT_PATH(@"/basebin/.fakelib/systemhook.dylib") error:nil];

		// Patch basebin plists
		NSURL *basebinDaemonsURL = [NSURL fileURLWithPath:JBROOT_PATH(@"/basebin/LaunchDaemons")];
		for (NSURL *basebinDaemonURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:basebinDaemonsURL includingPropertiesForKeys:nil options:0 error:nil]) {
			NSString *plistPath = basebinDaemonURL.path;
			NSMutableDictionary *plistDict = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
			if (plistDict) {
				bool madeChanges = NO;
				NSMutableArray *programArguments = ((NSArray *)plistDict[@"ProgramArguments"]).mutableCopy;
				for (NSString *argument in [programArguments reverseObjectEnumerator]) {
					if ([argument containsString:@"@JBROOT@"]) {
						programArguments[[programArguments indexOfObject:argument]] = [argument stringByReplacingOccurrencesOfString:@"@JBROOT@" withString:JBROOT_PATH(@"/")];
						madeChanges = YES;
					}
				}
				if (madeChanges) {
					plistDict[@"ProgramArguments"] = programArguments.copy;
					[plistDict writeToFile:plistPath atomically:NO];
				}
			}
		}

		NSString *newVersion = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/basebin/.version") encoding:NSUTF8StringEncoding error:nil];
		if (!newVersion) return 6;

		setenv("JBUPDATE_PREV_VERSION", prevVersion.UTF8String, 1);
		setenv("JBUPDATE_NEW_VERSION", newVersion.UTF8String, 1);
		return 0;
	}
}

void jbupdate_update_system_info(void)
{
	@autoreleasepool {
		// Load XPF
		void *xpfHandle = dlopen("@loader_path/libxpf.dylib", RTLD_NOW);
		if (!xpfHandle) {
			char msg[4000];
			snprintf(msg, 4000, "Dopamine: dlopening libxpf failed: (%s), cannot continue.", dlerror());
			abort_with_reason(7, 1, msg, 0);
			return;
		}
		int (*xpf_start_with_kernel_path)(const char *kernelPath) = dlsym(xpfHandle, "xpf_start_with_kernel_path");
		const char *(*xpf_get_error)(void) = dlsym(xpfHandle, "xpf_get_error");
		bool (*xpf_set_is_supported)(const char *name) = dlsym(xpfHandle, "xpf_set_is_supported");
		void (*xpf_stop)(void) = dlsym(xpfHandle, "xpf_stop");
		xpc_object_t (*xpf_construct_offset_dictionary)(const char *sets[]) = dlsym(xpfHandle, "xpf_construct_offset_dictionary");

		const char *kernelPath = prebootUUIDPath("/System/Library/Caches/com.apple.kernelcaches/kernelcache");
		xpc_object_t systemInfoXdict = NULL;

		// Rerun patchfinder
		int r = xpf_start_with_kernel_path(kernelPath);
		const char *error = NULL;
		if (r == 0) {
			char *sets[] = {
				"translation",
				"trustcache",
				"sandbox",
				"physmap",
				"struct",
				"physrw",
				"perfkrw",
				NULL,
				NULL,
				NULL,
				NULL,	
			};

			uint32_t idx = 7;
			if (xpf_set_is_supported("devmode")) {
				sets[idx++] = "devmode"; 
			}
			if (xpf_set_is_supported("badRecovery")) {
				sets[idx++] = "badRecovery"; 
			}
			if (xpf_set_is_supported("arm64kcall")) {
				sets[idx++] = "arm64kcall"; 
			}

			systemInfoXdict = xpf_construct_offset_dictionary((const char **)sets);
			if (!systemInfoXdict) {
				error = xpf_get_error();
			}
			xpf_stop();
		}
		else {
			xpf_stop();
			error = xpf_get_error();
		}

		if (error) {
			char msg[4000];
			snprintf(msg, 4000, "Dopamine: Updating system info via XPF failed with error: (%s), cannot continue.", error);
			abort_with_reason(7, 1, msg, 0);
			return;
		}

		dlclose(xpfHandle);

		// Get stuff that won't change from current info
		xpc_dictionary_set_uint64(systemInfoXdict, "kernelConstant.staticBase", kconstant(staticBase));
		xpc_dictionary_set_uint64(systemInfoXdict, "kernelConstant.slide", kconstant(slide));
		xpc_dictionary_set_uint64(systemInfoXdict, "kernelConstant.base", kconstant(base));
		xpc_dictionary_set_uint64(systemInfoXdict, "kernelConstant.virtBase", kconstant(virtBase));
		xpc_dictionary_set_uint64(systemInfoXdict, "kernelConstant.physBase", kconstant(physBase));
		xpc_dictionary_set_uint64(systemInfoXdict, "kernelConstant.physSize", kconstant(physSize));
		xpc_dictionary_set_uint64(systemInfoXdict, "kernelConstant.cpuTTEP", kconstant(cpuTTEP));
		xpc_dictionary_set_uint64(systemInfoXdict, "jailbreakInfo.usesPACBypass", jbinfo(usesPACBypass));
		xpc_dictionary_set_string(systemInfoXdict, "jailbreakInfo.rootPath", jbinfo(rootPath));

		// Rebuild gSystemInfo
		jbinfo_initialize_dynamic_offsets(systemInfoXdict);
		jbinfo_initialize_hardcoded_offsets();
	}
}

// Before primitives are retrieved
void jbupdate_finalize_stage1(const char *prevVersion, const char *newVersion)
{
	// Currently unused, reserved for the future
}

// After primitives are retrieved
void jbupdate_finalize_stage2(const char *prevVersion, const char *newVersion)
{
	jbupdate_update_system_info();

	// Legacy, this file is no longer used
	if (!access(JBROOT_PATH("/basebin/.idownloadd_enabled"), F_OK)) {
		remove(JBROOT_PATH("/basebin/.idownloadd_enabled"));
	}

	if (strcmp(prevVersion, "2.1") < 0 && strcmp(newVersion, "2.1") >= 0) {
		// Default value for this pref is true
		// Set it during jbupdate if prev version is <2.1 and new version is >=2.1
		gSystemInfo.jailbreakSettings.markAppsAsDebugged = true;

#ifndef __arm64e__
		// Initialize kcall only after we have the offsets required for it
		arm64_kcall_init();
#endif
	}

	JBFixMobilePermissions();
}