//
//  EONBackupUtil.h
//  Eon
//
//  Created by Denis Kutlubaev on 04.05.2018.
//  Copyright © 2018 Clarus. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ReactiveObjC.h"

@interface EONBackupUtil : NSObject

@property (nonatomic, strong) NSString *pinCode;
@property (nonatomic, strong) NSString *encryptedSeed;

- (instancetype)initWithPinCode:(NSString *)pinCode;

- (instancetype)initWithPinCode:(NSString *)pinCode encryptedSeed:(NSString *)encryptedSeed;

- (UIImage *)encryptedSeedQRImage;

- (NSString *)seedString;

- (NSArray *)seedArray;

- (BOOL)validateQRCode:(NSString *)seedString;

- (RACSignal *)decryptAndStoreSeed;

/**
 Проверка существования кошелька
 */
- (RACSignal *)validateAccount;

@end
