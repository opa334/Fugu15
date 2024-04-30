//
//  main.m
//  Dopamine
//
//  Created by Lars Fröder on 23.09.23.
//

#import <UIKit/UIKit.h>
#import "DOAppDelegate.h"

#import "DOEnvironmentManager.h"
#import <libjailbreak/info.h>
#import <libjailbreak/jbclient_xpc.h>

int main(int argc, char * argv[]) {
    if (argc >= 3) {
        if (!strcmp(argv[1], "trollstore")) {
            if (!strcmp(argv[2], "delete-bootstrap")) {
                [[DOEnvironmentManager sharedManager] deleteBootstrap];
            }
            else if (!strcmp(argv[2], "hide-jailbreak")) {
                [[DOEnvironmentManager sharedManager] setJailbreakHidden:YES];
            }
            return 0;
        }
    }
    
    if (argc >= 2) {
        // Legacy, called by Dopamine 1.x before initiating a jbupdate
        // As updating from 1.x to 2.x unsupported, just initiate a device reboot
        if (!strcmp(argv[1], "prepare_jbupdate")) {
            [[DOEnvironmentManager sharedManager] reboot];
            return 0;
        }
    }
    
    // If systemhook isn't loaded and we are already jailbroken, we need to do the checkin ourselves
    // This can happen when the jailbreak is hidden or when tweak injection into the Dopamine app is disabled via Choicy
    jbclient_process_checkin(NULL, NULL, NULL, NULL);
    
    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin:/var/jb/sbin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/usr/bin", 1);
        setenv("TERM", "xterm-256color", 1);
    }
    
    NSString * appDelegateClassName;
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([DOAppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
