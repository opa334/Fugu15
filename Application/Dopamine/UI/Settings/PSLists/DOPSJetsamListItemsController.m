//
//  DOPSExploitListItemsControllerViewController.m
//  Dopamine
//
//  Created by Lars Fröder on 29.04.24.
//

#import "DOPSJetsamListItemsController.h"
#import "DOUIManager.h"

@interface DOPSJetsamListItemsController ()

@end

@implementation DOPSJetsamListItemsController

- (NSArray *)specifiers
{
    if (!_specifiers) {
        _specifiers = [super specifiers];
        PSSpecifier *jetsamDescriptionSpecifier = [PSSpecifier emptyGroupSpecifier];
        [jetsamDescriptionSpecifier setProperty:DOLocalizedString(@"Jetsam_Description") forKey:@"footerText"];
        [(NSMutableArray *)_specifiers addObject:jetsamDescriptionSpecifier];
    }
    return _specifiers;
}

@end
