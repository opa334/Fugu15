#include <choma/FAT.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <mach-o/dyld.h>
#include "trustcache.h"

#import <Foundation/Foundation.h>

MachO *ljb_fat_find_preferred_slice(FAT *fat)
{
	cpu_type_t cputype;
	cpu_subtype_t cpusubtype;
	if (host_get_cpu_information(&cputype, &cpusubtype) != 0) { return NULL; }
	
	MachO *candidateSlice = NULL;

	if (cpusubtype == CPU_SUBTYPE_ARM64E) {
		// New arm64e ABI
		candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2);
		if (!candidateSlice) {
			// Old arm64e ABI
			candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64E);
			if (candidateSlice) {
				// If we found an old arm64e slice, make sure this is a library! If it's a binary, skip!!!
				// For binaries the system will fall back to the arm64 slice, which has the CDHash that we want to add
				if (macho_get_filetype(candidateSlice) == MH_EXECUTE) candidateSlice = NULL;
			}
		}
	}

	if (!candidateSlice) {
		// On iOS 15+ the kernels prefers ARM64_V8 to ARM64_ALL
		candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_V8);
		if (!candidateSlice) {
			candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_ALL);
		}
	}

	return candidateSlice;
}

bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *superblob)
{
	CS_DecodedBlob *wrapperBlob = csd_superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT, NULL);
	if (wrapperBlob) {
		if (csd_blob_get_size(wrapperBlob) > 8) {
			return false;
		}
	}
	return true;
}

NSString *resolveDependencyPath(NSString *dylibPath, NSString *sourceImagePath, NSString *sourceExecutablePath)
{
	@autoreleasepool {
		if (!dylibPath) return nil;
		NSString *loaderPath = [sourceImagePath stringByDeletingLastPathComponent];
		NSString *executablePath = [sourceExecutablePath stringByDeletingLastPathComponent];

		NSString *resolvedPath = nil;

		NSString *(^resolveLoaderExecutablePaths)(NSString *) = ^NSString *(NSString *candidatePath) {
			if (!candidatePath) return nil;
			if ([[NSFileManager defaultManager] fileExistsAtPath:candidatePath]) return candidatePath;
			if ([candidatePath hasPrefix:@"@loader_path"] && loaderPath) {
				NSString *loaderCandidatePath = [candidatePath stringByReplacingOccurrencesOfString:@"@loader_path" withString:loaderPath];
				if ([[NSFileManager defaultManager] fileExistsAtPath:loaderCandidatePath]) return loaderCandidatePath;
			}
			if ([candidatePath hasPrefix:@"@executable_path"] && executablePath) {
				NSString *executableCandidatePath = [candidatePath stringByReplacingOccurrencesOfString:@"@executable_path" withString:executablePath];
				if ([[NSFileManager defaultManager] fileExistsAtPath:executableCandidatePath]) return executableCandidatePath;
			}
			return nil;
		};

		if ([dylibPath hasPrefix:@"@rpath"]) {
			NSString *(^resolveRpaths)(NSString *) = ^NSString *(NSString *binaryPath) {
				if (!binaryPath) return nil;
				__block NSString *rpathResolvedPath = nil;
				FAT *fat = fat_init_from_path(binaryPath.fileSystemRepresentation);
				if (fat) {
					MachO *macho = ljb_fat_find_preferred_slice(fat);
					if (macho) {
						macho_enumerate_rpaths(macho, ^(const char *rpathC, bool *stop) {
							if (rpathC) {
								NSString *rpath = [NSString stringWithUTF8String:rpathC];
								if (rpath) {
									rpathResolvedPath = resolveLoaderExecutablePaths([dylibPath stringByReplacingOccurrencesOfString:@"@rpath" withString:rpath]);
									if (rpathResolvedPath) {
										*stop = true;
									}
								}
							}
						});
					}
					fat_free(fat);
				}
				return rpathResolvedPath;
			};

			resolvedPath = resolveRpaths(sourceImagePath);
			if (resolvedPath) return resolvedPath;

			// TODO: Check if this is even neccessary
			resolvedPath = resolveRpaths(sourceExecutablePath);
			if (resolvedPath) return resolvedPath;
		}
		else {
			resolvedPath = resolveLoaderExecutablePaths(dylibPath);
			if (resolvedPath) return resolvedPath;
		}
		
		return nil;
	}
}

void macho_collect_untrusted_cdhashes(const char *path, const char *callerImagePath, const char *callerExecutablePath, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	@autoreleasepool {
		if (!path) return;

		__block cdhash_t *cdhashes = NULL;
		__block uint32_t cdhashCount = 0;

		bool (^cdhashesContains)(cdhash_t) = ^bool(cdhash_t cdhash) {
			for (int i = 0; i < cdhashCount; i++) {
				if (!memcmp(cdhashes[i], cdhash, sizeof(cdhash_t))) {
					return true;
				}
			}
			return false;
		};

		void (^cdhashesAdd)(cdhash_t) = ^(cdhash_t cdhash) {
			cdhashCount++;
			cdhashes = realloc(cdhashes, cdhashCount * sizeof(cdhash_t));
			memcpy(cdhashes[cdhashCount-1], cdhash, sizeof(cdhash_t));
		};

		if (!callerExecutablePath) {
			FAT *mainFAT = fat_init_from_path(path);
			if (mainFAT) {
				MachO *mainMachO = ljb_fat_find_preferred_slice(mainFAT);
				if (mainMachO) {
					if (macho_get_filetype(mainMachO) == MH_EXECUTE) {
						callerExecutablePath = path;
					}
				}
				fat_free(mainFAT);
			}
		}
		if (!callerImagePath) {
			if (!access(path, F_OK)) {
				callerImagePath = path;
			}
		}

		__weak __block void (^binaryTrustHandler_recurse)(NSString *, NSString *, NSString *);
		void (^binaryTrustHandler)(NSString *, NSString *, NSString *) = ^(NSString *binaryPath, NSString *sourceImagePath, NSString *sourceExecutablePath) {
			NSString *resolvedBinaryPath = resolveDependencyPath(binaryPath, sourceImagePath, sourceExecutablePath);
			FAT *fat = fat_init_from_path(resolvedBinaryPath.fileSystemRepresentation);
			if (!fat) return;
			MachO *macho = ljb_fat_find_preferred_slice(fat);
			if (!macho) {
				fat_free(fat);
				return;
			}

			// Calculate cdhash and add it to our array
			bool cdhashWasKnown = true;
			bool isAdhocSigned = false;
			CS_SuperBlob *superblob = macho_read_code_signature(macho);
			if (superblob) {
				CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
				if (decodedSuperblob) {
					if (csd_superblob_is_adhoc_signed(decodedSuperblob)) {
						isAdhocSigned = true;
						cdhash_t cdhash;
						if (csd_superblob_calculate_best_cdhash(decodedSuperblob, cdhash) == 0) {
							if (!cdhashesContains(cdhash)) {
								if (!is_cdhash_trustcached(cdhash)) {
									// If something is trustcached we do not want to add it to your array
									// We do want to parse it's dependencies however, as one may have been updated since we added the binary to trustcache
									// Potential optimization: If trustcached, save in some array so we don't recheck
									cdhashesAdd(cdhash);
								}
								cdhashWasKnown = false;
							}
						}
					}
					csd_superblob_free(decodedSuperblob);
				}
				free(superblob);
			}

			if (cdhashWasKnown || // If we already knew the cdhash, we can skip parsing dependencies
				!isAdhocSigned) { // If it was not ad hoc signed, we can safely skip it aswell
				fat_free(fat);
				return;
			}

			// Recurse this block on all dependencies
			macho_enumerate_dependencies(macho, ^(const char *dylibPathC, uint32_t cmd, struct dylib* dylib, bool *stop) {
				if (!dylibPathC) return;
				if (_dyld_shared_cache_contains_path(dylibPathC)) return;
				binaryTrustHandler_recurse([NSString stringWithUTF8String:dylibPathC], resolvedBinaryPath, sourceExecutablePath);
			});

			fat_free(fat);
		};
		binaryTrustHandler_recurse = binaryTrustHandler;

		binaryTrustHandler([NSString stringWithUTF8String:path], callerImagePath ? [NSString stringWithUTF8String:callerImagePath] : nil, callerExecutablePath ? [NSString stringWithUTF8String:callerExecutablePath] : nil);

		*cdhashesOut = cdhashes;
		*cdhashCountOut = cdhashCount;
	}
}