
@interface KGMusicToolyManager : NSObject
@end

@implementation KGMusicToolyManager

- (void)setUpTooly {
    // 1. 获取用户ID
    NSString *userId = [[UserOpBLL shareUserInfo] userID];
    
    // 2. 检查用户ID是否有效
    if (!userId || [userId length] == 0 || [userId isEqualToString:@"0"]) {
        // 3. 如果用户ID无效，从统计信息获取设备ID
        NSString *deviceId = [[KGTencentStatistics sharedInstance] q36];  // 获取设备标识
        userId = deviceId;  // 使用设备ID作为用户ID
    }
    
    // 4. 获取设备UDID
    NSString *deviceId = [StatisticInfo udid];
    // 5. 强制设置工具（非强制模式）
    [self forceSetUpToolyWithUserId:userId deviceId:deviceId force:NO];
}

- (void)forceSetUpToolyWithUserId:(NSString *)userId deviceId:(NSString *)deviceId force:(BOOL)force {
    // 1. 检查引擎是否已设置
    if ([self isSettedEngine]) {
        return;
    }
    
    // 2. 检查是否需要强制设置或引擎是否已开启
    if (!force &&  {
        [self resetRfixEvn];
        return;
    }
    
    // 3. 使用dispatch_once确保只执行一次
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        @autoreleasepool {
            // 4. 通知注册
            [[self notifyRegisterRfx] notifyRegisterRfx];
            
            // 5. 获取系统信息
            NSString *systemInfo = [NSString stringWithCString:sub_10CD9671C() encoding:NSUTF8StringEncoding];
            
            // 6. 执行特殊方法注册
            [[self specilMethodVarRegister] specilMethodVarRegister];
            
            // 7. 获取系统版本
            UIDevice *device = [UIDevice currentDevice];
            NSString *systemVersion = [device systemVersion];
            [device release];
            
            // 8. 准备参数
            const char *param1 = "27ad641a44";
            const char *param2 = "5b1ec752-1349-49af-aacb-f9d25197bce9";
            const char *userIdCStr = [userId UTF8String];
            const char *deviceIdCStr = [deviceId UTF8String];
            const char *param5 = "20449";
            const char *systemVersionCStr = [systemVersion UTF8String];
            
            // 9. 调用核心设置函数
            sub_10CD96778(param1, param2, 2, userIdCStr, deviceIdCStr, param5, systemVersionCStr);
            
            // 10. 标记引擎已设置
            [[self setIsSettedEngine] setIsSettedEngine:YES];
        }
    });
}

static dispatch_once_t onceToken;
void sub_10CD96778(
    const char *uid,
    const char *deviceID,
    const char *processor,
    const char *appKey,
    uint64_t flag,
    const char *appVersion,
    const char *systemVersion
) {
    dispatch_once(&onceToken, ^{
        ZBHWindowWindowTag *tag = [ZBHWindowWindowTag new];

        if (uid)
            tag.uid = [NSString stringWithCString:uid encoding:4];

        if (deviceID)
            tag.deviceID = [NSString stringWithCString:deviceID encoding:4];

        if (processor)
            tag.makeDoubleFromProcessor =
                [NSString stringWithCString:processor encoding:4];

        if (appKey)
            tag.appKey = [NSString stringWithCString:appKey encoding:4];

        if (flag)
            [tag setSetRealRightButton];

        if (appVersion)
            tag.appVersion =
                [NSString stringWithCString:appVersion encoding:4];

        if (systemVersion)
            tag.systemVersion =
                [NSString stringWithCString:systemVersion encoding:4];

        logSDKVersion("0.8.0-licensed-2");
        logAppInfo(appKey, flag, uid, deviceID, appVersion, systemVersion);

        submitTag(tag);
    });
}


@end


  3813 ms  0x10d2ba848 kugou!0xcd96848 (0x10cd96848)
0x1ca6027c8 libdispatch.dylib!_dispatch_client_callout
0x1ca5d2f40 libdispatch.dylib!_dispatch_once_callout
0x10d2ba7ec kugou!0xcd967ec (0x10cd967ec)
0x1072a9d80 kugou!0x6d85d80 (0x106d85d80)
0x1ca6027c8 libdispatch.dylib!_dispatch_client_callout
0x1ca5d2f40 libdispatch.dylib!_dispatch_once_callout
0x1072a9c70 kugou!-[KGMusicToolyManager forceSetUpToolyWithUserId:deviceId:force:]
0x1072a9ae8 kugou!-[KGMusicToolyManager setUpTooly]
0x109499ecc kugou!-[KGToolyTask afterStartInit]
0x10923df20 kugou!-[KGStartUpTaskManager pTaskObjectperform:queueKey:]
0x10923cd00 kugou!0x8d18d00 (0x108d18d00)
0x10923b698 kugou!-[KGStartUpTaskSysQueue runTasks:]
0x10923dbd8 kugou!-[KGStartUpTaskManager pRunQueueWithTasks:queueKey:]
0x10923c37c kugou!-[KGStartUpTaskManager pRunWithQueueKey:]
0x1065539cc kugou!-[KGListenMoudleLifecyleMounter appLauchWhenHomePageIsReadyDelay]