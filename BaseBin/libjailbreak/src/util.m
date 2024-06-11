#include "info.h"
#import <Foundation/Foundation.h>
#import "util.h"
#import <sys/stat.h>

NSString *NSJBRootPath(NSString *relativePath)
{
	@autoreleasepool {
		return [[NSString stringWithUTF8String:jbinfo(rootPath)] stringByAppendingPathComponent:relativePath];
	}
}

NSString *NSPrebootUUIDPath(NSString *relativePath)
{
	@autoreleasepool {
		return [NSString stringWithUTF8String:prebootUUIDPath(relativePath.UTF8String)];
	}
}

void _JBFixMobilePermissionsOfDirectory(NSString *directoryPath, BOOL recursive)
{
	struct stat s;
	NSURL *directoryURL = [NSURL fileURLWithPath:directoryPath];

	if (stat(directoryURL.fileSystemRepresentation, &s) == 0) {
		if (s.st_uid != 501 || s.st_gid != 501) {
			chown(directoryURL.fileSystemRepresentation, 501, 501);
		}
	}

	if (recursive) {
		NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtURL:directoryURL includingPropertiesForKeys:nil options:0 errorHandler:nil];
		for (NSURL *fileURL in enumerator) {
			if (stat(fileURL.fileSystemRepresentation, &s) == 0) {
				if (s.st_uid != 501 || s.st_gid != 501) {
					chown(fileURL.fileSystemRepresentation, 501, 501);
				}
			}
		}
	}
}

void JBFixMobilePermissions(void)
{
	@autoreleasepool {
		NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:NSJBRootPath(@"/var") error:nil];
		if ([attributes[NSFileType] isEqualToString:NSFileTypeSymbolicLink]) {
			// /var/jb/var is a symlink, abort
			return;
		}
		attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:NSJBRootPath(@"/var/mobile") error:nil];
		if ([attributes[NSFileType] isEqualToString:NSFileTypeSymbolicLink]) {
			// /var/jb/var/mobile is a symlink, abort
			return;
		}

		_JBFixMobilePermissionsOfDirectory(NSJBRootPath(@"/var/mobile"), NO);
		_JBFixMobilePermissionsOfDirectory(NSJBRootPath(@"/var/mobile/Library"), NO);
		_JBFixMobilePermissionsOfDirectory(NSJBRootPath(@"/var/mobile/Library/SplashBoard"), YES);
		_JBFixMobilePermissionsOfDirectory(NSJBRootPath(@"/var/mobile/Library/Application Support"), YES);
		_JBFixMobilePermissionsOfDirectory(NSJBRootPath(@"/var/mobile/Library/Preferences"), YES);
	}
}