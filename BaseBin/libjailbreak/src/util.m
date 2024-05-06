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

void JBFixMobilePermissions(void)
{
	@autoreleasepool {
		struct stat s;

		// Anything in /var/mobile should owned by mobile...
		// For some reason some packages seem to fuck this up, so we automatically fix it every userspace reboot and on rejailbreak
		NSString *mobilePath = NSJBRootPath(@"/var/mobile");
		NSURL *mobileURL = [NSURL fileURLWithPath:mobilePath];

		if (stat(mobileURL.fileSystemRepresentation, &s) == 0) {
			if (s.st_uid != 501 || s.st_gid != 501) {
				chown(mobileURL.fileSystemRepresentation, 501, 501);
			}
		}

		NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtURL:mobileURL includingPropertiesForKeys:nil options:0 errorHandler:nil];
		for (NSURL *fileURL in enumerator) {
			if (stat(fileURL.fileSystemRepresentation, &s) == 0) {
				if (s.st_uid != 501 || s.st_gid != 501) {
					chown(fileURL.fileSystemRepresentation, 501, 501);
				}
			}
		}
	}
}