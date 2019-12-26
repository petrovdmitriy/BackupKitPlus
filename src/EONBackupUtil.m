//
//  EONBackupUtil.m
//  Eon
//
//  Created by Denis Kutlubaev on 04.05.2018.
//  Copyright © 2018 Clarus. All rights reserved.
//

#import "EONBackupUtil.h"
#import "EONClientStore.h"
#import "Cryptography.h"
#import "NSData+XOR.h"
#import "Curve25519.h"
#import "EONTransactionList.h"
#import "EONServerConnector.h"
#import "EONPeer.h"
#import "EONTranslateManager.h"

@implementation EONBackupUtil

- (instancetype)initWithPinCode:(NSString *)pinCode
{
    self = [super init];
    
    if (self) {
        _pinCode = pinCode;
    }
    
    return self;
}

- (instancetype)initWithPinCode:(NSString *)pinCode encryptedSeed:(NSString *)encryptedSeed
{
    self = [self initWithPinCode:pinCode];
    
    if (self) {
        self.encryptedSeed = encryptedSeed;
    }
    
    return self;
}

- (OWSAES256Key *)pinCodeKey
{
    NSAssert([self.pinCode length] == 4, @"Pin code must have length of 4 symbols");
    NSData *pinCodeData = [self.pinCode dataUsingEncoding:NSUTF8StringEncoding];
    pinCodeData = [Cryptography computeSHA256Digest:pinCodeData];
    return [OWSAES256Key keyWithData:pinCodeData];
}

- (NSData *)pinCodeHash
{
    NSAssert([self.pinCode length] == 4, @"Pin code must have length of 4 symbols");
    NSData *pinCodeData = [self.pinCode dataUsingEncoding:NSUTF8StringEncoding];
    return [Cryptography computeSHA256Digest:pinCodeData];
}

- (NSString *)aesEncryptedSeedString
{
    NSData *seedData = [EONClientStore sharedStore].eonSeed;
    NSData *encryptedSeedData = [Cryptography encryptAESGCMWithData:seedData key:[self pinCodeKey]];
    NSString *encryptedSeedString = [encryptedSeedData description];
    encryptedSeedString = [encryptedSeedString stringByReplacingOccurrencesOfString:@"<" withString:@""];
    encryptedSeedString = [encryptedSeedString stringByReplacingOccurrencesOfString:@">" withString:@""];
    return encryptedSeedString;
}

- (NSString *)xorEncryptedSeedString
{
    NSData *seed = [EONClientStore sharedStore].eonSeed;
    NSData *pinHash = [self pinCodeHash];
    
    NSData *xorEncryptedSeedData = [NSData DataXOR1:seed DataXOR2:pinHash];
    NSString *xorEncryptedSeedString = [xorEncryptedSeedData description];
    xorEncryptedSeedString = [xorEncryptedSeedString stringByReplacingOccurrencesOfString:@"<" withString:@""];
    xorEncryptedSeedString = [xorEncryptedSeedString stringByReplacingOccurrencesOfString:@">" withString:@""];
    return xorEncryptedSeedString;
}

- (CIImage *)createQRForString:(NSString *)qrString
{
    NSData *stringData = [qrString dataUsingEncoding: NSUTF8StringEncoding];
    
    CIFilter *qrFilter = [CIFilter filterWithName:@"CIQRCodeGenerator"];
    [qrFilter setValue:stringData forKey:@"inputMessage"];
    
    return qrFilter.outputImage;
}

- (UIImage *)encryptedSeedQRImage
{
    CIImage *image = [self createQRForString:[self xorEncryptedSeedString]];
    CGAffineTransform transform = CGAffineTransformMakeScale(15.0f, 15.0f); // Scale by 15 times along both dimensions
    CIImage *output = [image imageByApplyingTransform: transform];
    UIImage *originalImage = [UIImage imageWithCIImage:output];
    UIGraphicsBeginImageContext(originalImage.size);
    [originalImage drawInRect:CGRectMake(0, 0, originalImage.size.width, originalImage.size.height)];
    UIImage *qrCodeImage = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return qrCodeImage;
}

- (NSString *)seedString
{
    NSData *seedData = [EONClientStore sharedStore].eonSeed;
    NSString *seedString = [seedData description];
    seedString = [seedString stringByReplacingOccurrencesOfString:@"<" withString:@""];
    seedString = [seedString stringByReplacingOccurrencesOfString:@">" withString:@""];
    return seedString;
}

- (NSArray *)seedArray
{
    NSArray *seedArray = [[self xorEncryptedSeedString] componentsSeparatedByString:@" "];
    return seedArray;
}

- (BOOL)validateQRCode:(NSString *)seedString
{
    return [seedString isEqualToString:[self xorEncryptedSeedString]];
}

- (RACSignal *)decryptAndStoreSeed
{
    return [RACSignal createSignal:^RACDisposable * _Nullable(id<RACSubscriber>  _Nonnull subscriber) {
    
        self.encryptedSeed = [NSString stringWithFormat:@"<%@>", self.encryptedSeed];
        
        if (! self.pinCode || ! self.encryptedSeed) {
            NSError *error = [[NSError alloc] initWithDomain:@"" code:0 userInfo:@{NSLocalizedDescriptionKey:NSLocalizedString(@"Empty PIN or secret key", nil)}];
            [subscriber sendError:error];
            [subscriber sendCompleted];
            
            return nil;
        }
        
        const char *ptr = [self.encryptedSeed cStringUsingEncoding:NSUTF8StringEncoding];
        
        NSMutableData *data = [NSMutableData data];
        
        while (*ptr) {
            unsigned char c1 = *ptr;
            ptr++;
            if (isalpha(c1))
                c1 = (10 + c1 - 'a')<<4;
            else if (isnumber(c1))
                c1 = (c1 - '0')<<4;
            else
                continue;
            if (!*ptr)
                break; // Shouldn't occure -- bad input
            unsigned char c2 = *ptr;
            ptr++;
            if (isalpha(c2))
                c2 = 10 + c2 - 'a';
            else if (isnumber(c2))
                c2 = c2 - '0';
            c1 = c1 | c2;
            [data appendBytes:&c1 length:1];
        }
        
        NSLog(@"%@", data);
        
        NSData *encryptedSeed = [NSData dataWithData:data];
        NSData *pinHash = [self pinCodeHash];
        NSData *seed = [NSData DataXOR1:encryptedSeed DataXOR2:pinHash];
        
        NSMutableData *mutableSeedData = [[NSMutableData alloc] initWithData:seed];
        
        unsigned char *bits = [mutableSeedData mutableBytes];
        NSError *error = nil;
        EONClientStore* store = [EONClientStore sharedStore];
        store.eonKey = [EonSignKeypair generateUseSeed:bits error:&error];
        if (error) {
            [subscriber sendError:error];
            return nil;
        }
        NSMutableData *dataH = [[Curve25519 cryptoHashSha512:store.eonKey.publicKey] mutableCopy];
        unsigned char *hash = [dataH mutableBytes];
        uint64_t rez = 0;
        for (int i = 0; i < 64; i += 8) {
            uint64_t r1 = 0;
            r1 = ((uint64_t)hash[i] | ((uint64_t)hash[i + 1] << 8) | ((uint64_t)hash[i + 2] << 16) | ((uint64_t)hash[i + 3] << 24)
                  | ((uint64_t)hash[i + 4] << 32) | ((uint64_t)hash[i + 5] << 40) | ((uint64_t)hash[i + 6] << 48) | ((uint64_t)hash[i + 7] << 56));
            rez ^= r1;
        }
        
        store.eonLongID = rez;
        store.eonID = [self userFriendlyID:rez];
        store.eonSeed = seed;
        
        [store saveChanges];
        
        [subscriber sendNext:@(YES)];
        [subscriber sendCompleted];
        
        return nil;
    }];
}

-(NSString*)userFriendlyID:(uint64_t)plain
{
    uint64_t id1 = plain;
    uint64_t id2 = 0;
    uint64_t chs = 0;
    uint64_t andVal = 0x3FF;
    uint64_t tmpId = id1;
    while (tmpId > 0) {
        chs ^= (tmpId & andVal);
        tmpId = tmpId >> 10;
        if(id2 && tmpId >> 10 == 0) {
            tmpId += id2 << 1;
            id2 = 0;
        }
    }
    
    chs = chs | 0x400;
    
    NSString* strABC = @"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    NSString* idStr = EON_code;
    andVal = 0b11111;
    
    int i = 0;
    for(; i < 15; ++i) {
        if (i % 5 == 0) {
            idStr = [idStr stringByAppendingString:@"-"];
        }
        NSUInteger loc = (unsigned int)(id1 & andVal);
        NSRange range = NSMakeRange(loc, 1);
        idStr = [idStr stringByAppendingString:[strABC substringWithRange:range] ];
        tmpId = i == 11 ? (chs << 9 | id1) : id1;
        id1 = tmpId >> 5;
    }
    
    return idStr;
}

- (RACSignal *)validateAccount
{
    return [[EONPeer sharedPeer] validateAccount];
}

@end
