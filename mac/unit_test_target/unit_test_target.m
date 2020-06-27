//
//  unit_test_target.m
//  unit_test_target
//
//  Created by kkAyataka on 2020/06/27.
//  Copyright © 2020 kkAyataka. All rights reserved.
//

#import <XCTest/XCTest.h>

#include "gtest/gtest.h"

#include <iostream>


@interface unit_test_target : XCTestCase

@end

@implementation unit_test_target

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testAll {
    NSArray * args = [[NSProcessInfo processInfo] arguments];
    int argc = (int)args.count;
    char const * argv[10] = {};
    for (int i = 0; i < argc; ++i) {
        argv[i] = [[args objectAtIndex: i] cStringUsingEncoding: NSUTF8StringEncoding];
    }

    std::cout << "Running main() from " << __FILE__ << std::endl;
    testing::InitGoogleTest(&argc, (char**)argv);
    RUN_ALL_TESTS();
}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
