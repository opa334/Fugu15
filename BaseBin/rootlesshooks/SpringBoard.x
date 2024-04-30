#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/objc.h>
#import <libroot.h>

@interface XBSnapshotContainerIdentity : NSObject <NSCopying>
@property (nonatomic, readonly, copy) NSString* bundleIdentifier;
- (NSString*)snapshotContainerPath;
@end

%hook XBSnapshotContainerIdentity

- (NSString *)snapshotContainerPath
{
	NSString *path = %orig;
	if([path hasPrefix:@"/var/mobile/Library/SplashBoard/Snapshots/"] && ![self.bundleIdentifier hasPrefix:@"com.apple."]) {
		return JBROOT_PATH_NSSTRING(path);
	}
	return path;
}

%end

void springboardInit(void)
{
	%init();
}
