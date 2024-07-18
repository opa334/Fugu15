//
//  NSString+Version.h
//  Dopamine
//
//  Created by Lars Fröder on 12.06.24.
//

#import <Foundation/Foundation.h>

@implementation NSString (Version)

- (NSInteger)numericalVersionRepresentation
{
    NSInteger numericalRepresentation = 0;

    NSArray *components = [self componentsSeparatedByCharactersInSet:[[NSCharacterSet decimalDigitCharacterSet] invertedSet]];
    while (components.count < 3)
        components = [components arrayByAddingObject:@"0"];

    numericalRepresentation |= [components[0] integerValue] << 16;
    numericalRepresentation |= [components[1] integerValue] << 8;
    numericalRepresentation |= [components[2] integerValue];
    return numericalRepresentation;
}

@end
