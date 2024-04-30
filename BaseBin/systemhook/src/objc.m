#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#include <libjailbreak/jbclient_xpc.h>
#import "common.h"
#import <os/log.h>

// If you ever wondered how to hook an Objective C method without linking anything (Foundation/libobjc), this is how

extern char **environ;

id (*__objc_getClass)(const char *name);
id (*__objc_alloc)(Class cls);
void (*__objc_release)(id obj);
void *(*__objc_msgSend_0)(id self, SEL _cmd);
void *(*__objc_msgSend_1)(id self, SEL _cmd, void *a1);
void *(*__objc_msgSend_2)(id self, SEL _cmd, void *a1, void *a2);
void *(*__objc_msgSend_3)(id self, SEL _cmd, void *a1, void *a2, void *a3);
void *(*__objc_msgSend_4)(id self, SEL _cmd, void *a1, void *a2, void *a3, void *a4);
void *(*__objc_msgSend_5)(id self, SEL _cmd, void *a1, void *a2, void *a3, void *a4, void *a5);
void *(*__objc_msgSend_6)(id self, SEL _cmd, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6);
IMP (*__class_replaceMethod)(Class cls, SEL name, IMP imp, const char *types);

bool (*NSConcreteTask_launchWithDictionary_error__orig)(id self, id sender, NSDictionary *dictionary, NSError **errorOut);
bool NSConcreteTask_launchWithDictionary_error__hook(id self, id sender, NSDictionary *dictionary, NSError **errorOut)
{
	if (dictionary) {
		Class NSString_class = __objc_getClass("NSString");
		Class NSMutableDictionary_class = __objc_getClass("NSMutableDictionary");

		NSString *keyExecutablePath = __objc_msgSend_1(__objc_alloc(NSString_class), @selector(initWithUTF8String:), "_NSTaskExecutablePath");
		NSString *keyEnvironmentDict = __objc_msgSend_1(__objc_alloc(NSString_class), @selector(initWithUTF8String:), "_NSTaskEnvironmentDictionary");
		NSString *dyldInsertLibraries = __objc_msgSend_1(__objc_alloc(NSString_class), @selector(initWithUTF8String:), "DYLD_INSERT_LIBRARIES");
		NSString *hookDylibPath = __objc_msgSend_1(__objc_alloc(NSString_class), @selector(initWithUTF8String:), HOOK_DYLIB_PATH);

		NSString *executablePath = __objc_msgSend_1(dictionary, @selector(objectForKey:), keyExecutablePath);
		if (executablePath) {
			const char *executablePathC = __objc_msgSend_0(executablePath, @selector(UTF8String));
			jbclient_trust_binary(executablePathC);
		}

		NSDictionary *existingEnvironment = __objc_msgSend_1(dictionary, @selector(objectForKey:), keyEnvironmentDict);
		NSMutableDictionary *mutableEnvironment;
		if (existingEnvironment) {
			// Easy
			mutableEnvironment = __objc_msgSend_0(existingEnvironment, @selector(mutableCopy));
		}
		else {
			// Pain...
			mutableEnvironment = __objc_msgSend_0(__objc_alloc(NSMutableDictionary_class), @selector(init));

			int i = 0;
			while(environ[i]) {
				char *key = NULL;
				char *value = NULL;
				char *full = strdup(environ[i++]);
				char *tok = strtok(full, "=");
				if (tok) {
					key = strdup(tok);
					tok = strtok(NULL, "=");
					if (tok) {
						value = strdup(tok);
					}
				}
				if (full) free(full);

				if (key && value) {
					NSString *nsKey = __objc_msgSend_1(__objc_alloc(NSString_class), @selector(initWithUTF8String:), key);
					NSString *nsValue = __objc_msgSend_1(__objc_alloc(NSString_class), @selector(initWithUTF8String:), value);
					if (nsKey && nsValue) {
						__objc_msgSend_2(mutableEnvironment, @selector(setObject:forKey:), nsValue, nsKey);
					}
					if (nsKey) __objc_release(nsKey);
					if (nsValue) __objc_release(nsValue);
				}
				if (key) free(key);
				if (value) free(value);
			}
		}

		NSDictionary *mutableLaunchDictionary = __objc_msgSend_0(dictionary, @selector(mutableCopy));
		__objc_msgSend_2(mutableEnvironment, @selector(setObject:forKey:), hookDylibPath, dyldInsertLibraries);
		__objc_msgSend_2(mutableLaunchDictionary, @selector(setObject:forKey:), mutableEnvironment, keyEnvironmentDict);

		bool r = NSConcreteTask_launchWithDictionary_error__orig(self, sender, dictionary, errorOut);

		__objc_release(mutableEnvironment);
		__objc_release(mutableLaunchDictionary);
		__objc_release(keyExecutablePath);
		__objc_release(keyEnvironmentDict);
		__objc_release(dyldInsertLibraries);
		__objc_release(hookDylibPath);
		return r;
	}
	else {
		return NSConcreteTask_launchWithDictionary_error__orig(self, sender, dictionary, errorOut);;
	}
}

void dopamine_fix_NSTask(void)
{
	// This only works if libobjc and Foundation are already loaded, that is by design
	// So as of right now it only automatically works if some tweak is loaded (as libellekit depends on Foundation)
	// If you want to use NSTask in your app or whatever, call this function yourself after Foundation is loaded
	// This could be automated but it's difficult due to image loading callbacks being shit
	void *libobjcHandle = dlopen("/usr/lib/libobjc.A.dylib", RTLD_NOLOAD);
	void *foundationHandle = dlopen("/System/Library/Frameworks/Foundation.framework/Foundation", RTLD_NOLOAD);
	if (libobjcHandle && foundationHandle) {
		static dispatch_once_t onceToken;
		dispatch_once (&onceToken, ^{
			__objc_getClass = dlsym(libobjcHandle, "objc_getClass");
			__objc_alloc = dlsym(libobjcHandle, "objc_alloc");
			__objc_release = dlsym(libobjcHandle, "objc_release");

			void *objc_msgSend = dlsym(libobjcHandle, "objc_msgSend");
			__objc_msgSend_0 = objc_msgSend;
			__objc_msgSend_1 = objc_msgSend;
			__objc_msgSend_2 = objc_msgSend;
			__objc_msgSend_3 = objc_msgSend;
			__objc_msgSend_4 = objc_msgSend;
			__objc_msgSend_5 = objc_msgSend;
			__objc_msgSend_6 = objc_msgSend;

			__class_replaceMethod = dlsym(libobjcHandle, "class_replaceMethod");

			Class NSConcreteTask_class = __objc_getClass("NSConcreteTask");
			NSConcreteTask_launchWithDictionary_error__orig = (void *)__class_replaceMethod(NSConcreteTask_class, @selector(launchWithDictionary:error:), (IMP)NSConcreteTask_launchWithDictionary_error__hook, "B@:@^@");
		});
	}
}