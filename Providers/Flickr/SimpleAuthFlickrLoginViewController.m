//
//  SimpleAuthFlickrLoginViewController.m
//  SimpleAuth
//
//  Created by Caleb Davenport on 1/16/14.
//  Copyright (c) 2014 Byliner, Inc. All rights reserved.
//

#import "SimpleAuthFlickrLoginViewController.h"

@implementation SimpleAuthFlickrLoginViewController

#pragma mark - SimpleAuthWebViewController

- (instancetype)initWithOptions:(NSDictionary *)options requestToken:(NSDictionary *)requestToken {
    if ((self = [super initWithOptions:options requestToken:requestToken])) {
        self.title = @"flickr";
    }
    return self;
}


- (NSURLRequest *)initialRequest {
    NSDictionary *parameters = @{
        @"oauth_token" : self.requestToken[@"oauth_token"],
    };
    NSString *URLString = [NSString stringWithFormat:
                           @"http://www.flickr.com/services/oauth/authorize?%@",
                           [CMDQueryStringSerialization queryStringWithDictionary:parameters]];
    NSURL *URL = [NSURL URLWithString:URLString];
    
    return [NSURLRequest requestWithURL:URL];
}

@end
