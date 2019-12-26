//
//  Copyright (c) 2017 Open Whisper Systems. All rights reserved.
//

#import <XCTest/XCTest.h>

#import <AxolotlKit/SignedPrekeyRecord.h>

#import "TSPreKeyManager.h"
#import "TSStorageManager+SignedPreKeyStore.h"

@interface  TSPreKeyManager (Testing)

+ (void)clearSignedPreKeyRecordsWithKeyId:(NSNumber *)keyId success:(void (^_Nullable)())successHandler;

@end

@interface SignedPreKeyDeletionTests : XCTestCase

@end

@implementation SignedPreKeyDeletionTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testSignedPreKeyDeletion {
    [[TSStorageManager sharedManager].dbReadWriteConnection
        readWriteWithBlock:^(YapDatabaseReadWriteTransaction *transaction) {
            [transaction removeAllObjectsInCollection:TSStorageManagerSignedPreKeyStoreCollection];
        }];

    int days = 20;
    int lastPreKeyId = days;

    for (int i = 0; i <= days; i++) { // 21 signed keys are generated, one per day from now until 20 days ago.
        int secondsAgo = (i - days) * 24 * 60 * 60;
        NSAssert(secondsAgo <= 0, @"Time in past must be negative");
        NSDate *generatedAt = [NSDate dateWithTimeIntervalSinceNow:secondsAgo];
        SignedPreKeyRecord *record = [[SignedPreKeyRecord alloc] initWithId:i keyPair:[Curve25519 generateKeyPair] signature:nil generatedAt:generatedAt];
        [[TSStorageManager sharedManager] storeSignedPreKey:i signedPreKeyRecord:record];
    }

    NSArray<SignedPreKeyRecord *> *signedPreKeys = [[TSStorageManager sharedManager] loadSignedPreKeys];
    // Sanity check
    XCTAssert(signedPreKeys.count == 21);

    XCTestExpectation *expection = [self expectationWithDescription:@"successfully cleared old keys"];
    [TSPreKeyManager
        clearSignedPreKeyRecordsWithKeyId:[NSNumber numberWithInt:lastPreKeyId]
                                  success:^{

                                      XCTAssert(
                                          [[TSStorageManager sharedManager] loadSignedPrekey:lastPreKeyId] != nil);

                                      // We'll delete every key created 7 or more days ago.
                                      NSArray<SignedPreKeyRecord *> *signedPreKeys =
                                          [[TSStorageManager sharedManager] loadSignedPreKeys];
                                      XCTAssert(signedPreKeys.count == 7);
                                      [expection fulfill];
                                  }];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testSignedPreKeyDeletionKeepsSomeOldKeys
{
    [[TSStorageManager sharedManager].dbReadWriteConnection
        readWriteWithBlock:^(YapDatabaseReadWriteTransaction *transaction) {
            [transaction removeAllObjectsInCollection:TSStorageManagerSignedPreKeyStoreCollection];
        }];

    int lastPreKeyId = 10;
    for (int i = 0; i <= 10; i++) {
        // All these keys will be considered "old", since they were created more than 7 days ago.
        int secondsAgo = (i - 20) * 24 * 60 * 60;
        NSAssert(secondsAgo <= 0, @"Time in past must be negative");
        NSDate *generatedAt = [NSDate dateWithTimeIntervalSinceNow:secondsAgo];
        SignedPreKeyRecord *record = [[SignedPreKeyRecord alloc] initWithId:i
                                                                    keyPair:[Curve25519 generateKeyPair]
                                                                  signature:nil
                                                                generatedAt:generatedAt];
        // we only retain accepted keys
        [record markAsAcceptedByService];
        [[TSStorageManager sharedManager] storeSignedPreKey:i signedPreKeyRecord:record];
    }


    NSArray<SignedPreKeyRecord *> *signedPreKeys = [[TSStorageManager sharedManager] loadSignedPreKeys];
    // Sanity check
    XCTAssert(signedPreKeys.count == 11);

    XCTestExpectation *expection = [self expectationWithDescription:@"successfully cleared old keys"];
    [TSPreKeyManager
        clearSignedPreKeyRecordsWithKeyId:[NSNumber numberWithInt:lastPreKeyId]
                                  success:^{

                                      XCTAssert(
                                          [[TSStorageManager sharedManager] loadSignedPrekey:lastPreKeyId] != nil);

                                      NSArray<SignedPreKeyRecord *> *signedPreKeys =
                                          [[TSStorageManager sharedManager] loadSignedPreKeys];

                                      // We need to keep 3 "old" keys, plus the "current" key
                                      XCTAssert(signedPreKeys.count == 4);
                                      [expection fulfill];
                                  }];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testOlderRecordsNotDeletedIfNoReplacement {
    [[TSStorageManager sharedManager].dbReadWriteConnection
        readWriteWithBlock:^(YapDatabaseReadWriteTransaction *transaction) {
            [transaction removeAllObjectsInCollection:TSStorageManagerSignedPreKeyStoreCollection];
        }];

    int days = 3;
    int lastPreKeyId = days;

    for (int i = 0; i <= days; i++) { // 4 signed keys are generated, one per day from now until 3 days ago.
        int secondsAgo = (i - days) * 24 * 60 * 60;
        NSAssert(secondsAgo <= 0, @"Time in past must be negative");
        NSDate *generatedAt = [NSDate dateWithTimeIntervalSinceNow:secondsAgo];
        SignedPreKeyRecord *record = [[SignedPreKeyRecord alloc] initWithId:i keyPair:[Curve25519 generateKeyPair] signature:nil generatedAt:generatedAt];
        [[TSStorageManager sharedManager] storeSignedPreKey:i signedPreKeyRecord:record];
    }

    NSArray<SignedPreKeyRecord *> *signedPreKeys = [[TSStorageManager sharedManager] loadSignedPreKeys];
    // Sanity check
    XCTAssert(signedPreKeys.count == 4);

    XCTestExpectation *expection = [self expectationWithDescription:@"successfully cleared old keys"];
    [TSPreKeyManager
        clearSignedPreKeyRecordsWithKeyId:[NSNumber numberWithInt:lastPreKeyId]
                                  success:^{
                                      XCTAssert(
                                          [[TSStorageManager sharedManager] loadSignedPrekey:lastPreKeyId] != nil);
                                      // All three records should still be stored.
                                      NSArray<SignedPreKeyRecord *> *signedPreKeys =
                                          [[TSStorageManager sharedManager] loadSignedPreKeys];
                                      XCTAssert(signedPreKeys.count == 4);
                                      [expection fulfill];
                                  }];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

@end
