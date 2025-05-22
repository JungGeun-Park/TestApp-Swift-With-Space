//
//  AppSealingFramework.h
//  AppSealingFramework
//
//  Created by Hyeseon Oh on 11/27/24.
//  Copyright © 2024 Inka. All rights reserved.
//

#import <Foundation/Foundation.h>

//! Project version number for AppSealingFramework.
FOUNDATION_EXPORT double AppSealingFrameworkVersionNumber;

//! Project version string for AppSealingFramework.
FOUNDATION_EXPORT const unsigned char AppSealingFrameworkVersionString[];

// In this header, you should import all the public headers of your framework using statements like #import <AppSealingFramework/PublicHeader.h>

@interface AppSealingInterface : NSObject
- ( int )_IsAbnormalEnvironmentDetected;
+ (void)_NotifySwizzlingDetected:(void (^)(NSString*))handler;
+ ( int )_ReturnSwizzlingDetected;
- ( const char* )_GetAppSealingDeviceID;
- ( const char* )_GetEncryptedCredential;
+ ( NSString* )_DSS: ( NSString* )string;  // Decrypt String (for Objective-C / Swift string)
+ ( NSString* )_DSC: ( char* )string;      // Decrypt String (for C string)
@end

const int kAppSealingErrorNone                = 0;
const int kAppSealingErrorJailbreakDetected   = 1 << 0;
const int kAppSealingErrorDRMDecrypted        = 1 << 1;
const int kAppSealingErrorDebugAttached       = 1 << 2;
const int kAppSealingErrorHashInfoCorrupted   = 1 << 3;
const int kAppSealingErrorCodesignCorrupted   = 1 << 4;
const int kAppSealingErrorHashModified        = 1 << 5;
const int kAppSealingErrorExecutableCorrupted = 1 << 6;
const int kAppSealingErrorCertificateChanged  = 1 << 7;
const int kAppSealingErrorBlacklistCorrupted  = 1 << 8;
const int kAppSealingErrorCheatToolDetected   = 1 << 9;
