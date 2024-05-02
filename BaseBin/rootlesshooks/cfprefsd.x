#import <Foundation/Foundation.h>
#import <substrate.h>

BOOL preferencePlistNeedsRedirection(NSString *plistPath)
{
	if ([plistPath hasPrefix:@"/private/var/mobile/Containers"] || [plistPath hasPrefix:@"/var/db"] || [plistPath hasPrefix:@"/var/jb"]) return NO;

	NSString *plistName = plistPath.lastPathComponent;

	if ([plistName hasPrefix:@"com.apple."] || [plistName hasPrefix:@"systemgroup.com.apple."] || [plistName hasPrefix:@"group.com.apple."]) return NO;

	NSArray *additionalSystemPlistNames = @[
		@".GlobalPreferences.plist",
		@".GlobalPreferences_m.plist",
		@"bluetoothaudiod.plist",
		@"NetworkInterfaces.plist",
		@"OSThermalStatus.plist",
		@"preferences.plist",
		@"osanalyticshelper.plist",
		@"UserEventAgent.plist",
		@"wifid.plist",
		@"dprivacyd.plist",
		@"silhouette.plist",
		@"nfcd.plist",
		@"kNPProgressTrackerDomain.plist",
		@"siriknowledged.plist",
		@"UITextInputContextIdentifiers.plist",
		@"mobile_storage_proxy.plist",
		@"splashboardd.plist",
		@"mobile_installation_proxy.plist",
		@"languageassetd.plist",
		@"ptpcamerad.plist",
		@"com.google.gmp.measurement.monitor.plist",
		@"com.google.gmp.measurement.plist",
	];

	return ![additionalSystemPlistNames containsObject:plistName];
}

%hookf(BOOL, _CFPrefsGetPathForTriplet, CFStringRef bundleIdentifier, CFStringRef user, BOOL byHost, CFStringRef path, UInt8 *buffer)
{
	BOOL orig = %orig(bundleIdentifier, user, byHost, path, buffer);

	if(orig && buffer && !access("/var/jb", F_OK))
	{
		NSString* origPath = [NSString stringWithUTF8String:(char*)buffer];
		BOOL needsRedirection = preferencePlistNeedsRedirection(origPath);
		if (needsRedirection) {
			//NSLog(@"Plist redirected to /var/jb: %@", origPath);
			strcpy((char*)buffer, "/var/jb");
			strcat((char*)buffer, origPath.UTF8String);
		}
	}

	return orig;
}

void cfprefsdInit(void)
{
	MSImageRef coreFoundationImage = MSGetImageByName("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
	if (coreFoundationImage) {
		%init(_CFPrefsGetPathForTriplet = MSFindSymbol(coreFoundationImage, "__CFPrefsGetPathForTriplet"));
	}
}