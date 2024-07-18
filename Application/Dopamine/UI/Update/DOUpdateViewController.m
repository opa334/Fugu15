//
//  DOUpdateViewController.m
//  Dopamine
//
//  Created by tomt000 on 06/02/2024.
//

#import "DOUpdateViewController.h"
#import "DOUpdateCircleView.h"
#import "DOActionMenuButton.h"
#import "DOGlobalAppearance.h"
#import "DODownloadViewController.h"
#import "DOUIManager.h"
#import "DOEnvironmentManager.h"
#import <CoreServices/LSApplicationProxy.h>

@interface DOUpdateViewController ()

@property (strong, nonatomic) UITextView *changelog;
@property (strong, nonatomic) NSString *lastestDownloadUrl;
@property (strong, nonatomic) CAGradientLayer *gradientMask;
@property (strong, nonatomic) UIView *changelogSuperview;
@property (strong, nonatomic) DOActionMenuButton *button;

@property (strong, nonatomic) NSString *fromTag;
@property (strong, nonatomic) NSString *toTag;

@end

@implementation DOUpdateViewController

- (id)initFromTag:(NSString *)fromTag toTag:(NSString *)toTag
{
    if (self = [super init])
    {
        self.fromTag = fromTag;
        self.toTag = toTag;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    UILabel *title = [[UILabel alloc] init];
    title.text = DOLocalizedString(@"Title_Changelog");
    title.font = [UIFont systemFontOfSize:24 weight:UIFontWeightMedium];
    title.textColor = [UIColor colorWithWhite:1.0 alpha:1.0];
    title.textAlignment = NSTextAlignmentCenter;
    title.translatesAutoresizingMaskIntoConstraints = NO;

    [self.view addSubview:title];

    [NSLayoutConstraint activateConstraints:@[
        [title.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [title.topAnchor constraintEqualToAnchor:self.view.topAnchor constant:20]
    ]];

    self.changelogSuperview = [[UIView alloc] init];
    self.changelogSuperview.translatesAutoresizingMaskIntoConstraints = NO;

    self.changelog = [[UITextView alloc] init];
    self.changelog.font = [UIFont systemFontOfSize:16];
    self.changelog.textColor = [UIColor colorWithWhite:1.0 alpha:1.0];
    self.changelog.backgroundColor = [UIColor clearColor];
    self.changelog.translatesAutoresizingMaskIntoConstraints = NO;
    self.changelog.editable = NO;
    self.changelog.textAlignment = NSTextAlignmentCenter;
    self.changelog.alpha = 0.7;

    NSMutableParagraphStyle * paragraphStyle = [[NSMutableParagraphStyle alloc] init];
    paragraphStyle.alignment = NSTextAlignmentCenter;

    [self.changelogSuperview addSubview:self.changelog];
    [self.view addSubview:self.changelogSuperview];

    [NSLayoutConstraint activateConstraints:@[
        [self.changelogSuperview.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:20],
        [self.changelogSuperview.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.changelogSuperview.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.changelogSuperview.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [self.changelog.topAnchor constraintEqualToAnchor:self.changelogSuperview.topAnchor],
        [self.changelog.leadingAnchor constraintEqualToAnchor:self.changelogSuperview.leadingAnchor],
        [self.changelog.trailingAnchor constraintEqualToAnchor:self.changelogSuperview.trailingAnchor],
        [self.changelog.bottomAnchor constraintEqualToAnchor:self.changelogSuperview.bottomAnchor]
    ]];


    //add a alpha gradient mask to changelog superview
    self.gradientMask = [CAGradientLayer layer];
    self.gradientMask.frame = self.changelogSuperview.bounds;
    self.gradientMask.colors = @[(id)[UIColor clearColor].CGColor, (id)[UIColor whiteColor].CGColor, (id)[UIColor whiteColor].CGColor, (id)[UIColor clearColor].CGColor];
    self.gradientMask.locations = @[@0.0, @0.01, @0.5, @0.87];
    self.changelogSuperview.layer.mask = self.gradientMask;

    BOOL envUpdate = [[DOUIManager sharedInstance] environmentUpdateAvailable];
    
    self.button = [DOActionMenuButton buttonWithAction:[UIAction actionWithTitle:DOLocalizedString(envUpdate ? @"Button_Update_Environment" : @"Button_Update") image:[UIImage systemImageNamed:@"arrow.down" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"update" handler:^(__kindof UIAction * _Nonnull action) {
        if (envUpdate)
        {
            self.button.enabled = NO;
            self.button.alpha = 0.5;
            NSError *error = [[DOEnvironmentManager sharedManager] updateEnvironment];
            if (error)
            {
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Error Updating Basebin" message:error.localizedDescription preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Close") style:UIAlertActionStyleDefault handler:nil]];
                [self presentViewController:alert animated:YES completion:nil];
            }
            return;
        }

        if (![DOEnvironmentManager sharedManager].isJailbroken || [[DOUIManager sharedInstance] launchedReleaseNeedsManualUpdate] || ![DOEnvironmentManager sharedManager].isInstalledThroughTrollStore)
        {
            if ([DOEnvironmentManager sharedManager].isInstalledThroughTrollStore) {
                LSApplicationProxy *tsAppProxy = [LSApplicationProxy applicationProxyForIdentifier:@"com.opa334.TrollStore"];
                if ([tsAppProxy.claimedURLSchemes containsObject:@"apple-magnifier"]) {
                    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:[@"apple-magnifier://install?url=" stringByAppendingString:self.lastestDownloadUrl]] options:@{} completionHandler:nil];
                    return;
                }
            }
            [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/opa334/Dopamine/releases"] options:@{} completionHandler:nil];
            return;
        }

        DODownloadViewController *downloadVC = [[DODownloadViewController alloc] initWithUrl:self.lastestDownloadUrl callback:^(NSURL * _Nonnull file) {
            NSLog(@"Downloaded %@", file);
            [[DOEnvironmentManager sharedManager] updateJailbreakFromTIPA:file.path];
        }];
        [(UINavigationController*)(self.parentViewController) pushViewController:downloadVC animated:YES];
    }] chevron:NO];
    
    self.button.translatesAutoresizingMaskIntoConstraints = NO;
    self.button.hidden = !envUpdate;
    [self.view addSubview:self.button];

    [NSLayoutConstraint activateConstraints:@[
        [self.button.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.button.heightAnchor constraintEqualToConstant:30],
        [self.button.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor constant:-20]
    ]];


    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self updateChangelog];
    });
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    self.gradientMask.frame = self.changelogSuperview.bounds;
}

#pragma mark - Fetching Changelog

- (void)updateChangelog
{
    NSArray *releases = [[DOUIManager sharedInstance] getUpdatesInRange:self.fromTag end:self.toTag];
    NSMutableParagraphStyle * paragraphStyle = [[NSMutableParagraphStyle alloc] init];
    paragraphStyle.alignment = NSTextAlignmentCenter;
    NSMutableAttributedString *changelogText = [[NSMutableAttributedString alloc] initWithString:@""];

    if (releases.count == 0)
    {
        [changelogText appendAttributedString:[[NSAttributedString alloc] initWithString:DOLocalizedString(@"Changelog_Unavailable_Text") attributes:@{NSFontAttributeName: [UIFont systemFontOfSize:18], NSForegroundColorAttributeName : [UIColor whiteColor], NSParagraphStyleAttributeName:paragraphStyle}]];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.changelog.attributedText = changelogText;
        });
        return;
    }

    [releases enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSDictionary *release = (NSDictionary*)obj;
        NSString *name = release[@"name"];
        NSString *body = release[@"body"];
        [changelogText appendAttributedString:[[NSAttributedString alloc] initWithString:[NSString stringWithFormat:@"%@\n", name] attributes:@{NSFontAttributeName: [UIFont boldSystemFontOfSize:18], NSForegroundColorAttributeName : [UIColor whiteColor], NSParagraphStyleAttributeName:paragraphStyle}]];
        [changelogText appendAttributedString:[[NSAttributedString alloc] initWithString:@"\n"]];
        
        NSAttributedStringMarkdownParsingOptions *parsingOptions = [[NSAttributedStringMarkdownParsingOptions alloc] init];
        parsingOptions.allowsExtendedAttributes = YES;
        parsingOptions.interpretedSyntax = NSAttributedStringMarkdownInterpretedSyntaxInlineOnlyPreservingWhitespace;

        NSMutableAttributedString *markdownStringMut = [[NSAttributedString alloc] initWithMarkdownString:body options:parsingOptions baseURL:nil error:nil].mutableCopy;
        
        [markdownStringMut addAttributes:@{NSFontAttributeName: [UIFont systemFontOfSize:16], NSForegroundColorAttributeName : [UIColor whiteColor], NSParagraphStyleAttributeName:paragraphStyle} range:NSMakeRange(0, markdownStringMut.length)];

        [changelogText appendAttributedString:markdownStringMut];
        
        [changelogText appendAttributedString:[[NSAttributedString alloc] initWithString:@"\n\n\n"]];
        if (idx == 0)
        {
            NSArray *assets = release[@"assets"];
            if (assets && assets.count > 0)
            {
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.lastestDownloadUrl = release[@"assets"][0][@"browser_download_url"];
                    self.button.hidden = NO;
                });
            }
        }
    }];
    [changelogText appendAttributedString:[[NSAttributedString alloc] initWithString:@"\n\n\n\n\n\n\n\n\n\n"]];
    dispatch_async(dispatch_get_main_queue(), ^{
        self.changelog.attributedText = changelogText;
    });
}

#pragma mark - Status Bar

- (UIStatusBarStyle)preferredStatusBarStyle
{
    return UIStatusBarStyleLightContent;
}


@end
