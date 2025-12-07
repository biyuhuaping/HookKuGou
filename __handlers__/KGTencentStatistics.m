 7639 ms  -[KGTencentStatistics forceRereshDeviceIDMachineName:0x2802b9b40 o36:0x2802b9b40]
  7639 ms  👉1482ec024f1effab71edd705000016319904（__NSCFString）
  7639 ms  👉1482ec024f1effab71edd705000016319904（__NSCFString）
  7639 ms  stack: 0x10bc607e8 kugou!-[KGTencentStatistics update:o36:]
0x102f0c820 kugou!-[OstarService updateO16:o36:]
0x102ee5ac4 kugou!-[Qmeiegtm qmei_evkj6p0:]
0x102ee7aac kugou!-[Qmeiegtm qmei_qrlegk:serverCode:]
0x102ee7518 kugou!-[Qmeiegtm qmei_e948ze8:code:]
0x102f01af4 kugou!0xb9af4 (0x1000b9af4)
0x10fa85570 kugou!0xcc3d570 (0x10cc3d570)
0x102ecaa2c kugou!0x82a2c (0x100082a2c)
0x102eca2a0 kugou!0x822a0 (0x1000822a0)
0x10bc6076c kugou!0x8e1876c (0x108e1876c)
0x190f8b7a8 libdispatch.dylib!_dispatch_call_block_and_release
0x190f8c780 libdispatch.dylib!_dispatch_client_callout
0x190f6de10 libdispatch.dylib!_dispatch_main_queue_drain
0x190f6da88 libdispatch.dylib!_dispatch_main_queue_callback_4CF$VARIANT$armv81
0x18a26d9ac CoreFoundation!__CFRUNLOOP_IS_SERVICING_THE_MAIN_DISPATCH_QUEUE__
0x18a251648 CoreFoundation!__CFRunLoopRun
  9225 ms  👈: 1482ec024f1effab71edd705000016319904（__NSCFString）


  - (void)setUpTencentStatics {
    if (![KGTencentStatistics isEnable]) {
        return;
    }

    [self setUpOStar];          // 重点：上面我们已经分析过 OStar 的流程
    [self setUpDengTa];         // 可能是另一套统计/埋点或上报
    [self getQimei];            // 读取/生成 Qimei (重要：设备指纹)

    // 创建每 10 秒触发的定时器，selector = q36Check:, repeats = YES
    NSTimer *t = [YYTimer timerWithTimeInterval:10.0 target:self selector:@selector(q36Check) repeats:YES];
    [self setQ36Timer:t];
    [t release];

    // 注册网络状态变化通知
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(reachabilityChanged:) name:_kReachabilityChangedNotification object:nil];
}

- (void)getQimei {
    // 加锁
    id lockObj = *(id *)((uint8_t *)self + 0x28);
    [lockObj lock];

    self.isFecthingQ36 = YES;

    // 1. 拿 JSON 字符串
    NSString *json = [self deviceIDMachineName];
    NSDictionary *dict = [NSDictionary dictionaryWithJSONString:json error:nil];

    // 2. 取出字段
    NSString *o16 = [dict stringForKeyKGSafe:@"o16"];
    NSString *o36 = [dict stringForKeyKGSafe:@"o36"];

    // 检查 "o32" 是否存在
    BOOL hasO32 = [[dict allKeys] containsObject:@"o32"];

    // 3. 如果 o16 或 o36 为空 或者 没有 o32 → 请求 Ostar 更新
    BOOL emptyO16 = [StringTool isEmptyStr:o16];
    BOOL emptyO36 = [StringTool isEmptyStr:o36];

    if (emptyO16 || emptyO36 || !hasO32) {
        __weak typeof(self) weakSelf = self;
        [[OstarService shareInstance] forceUpdateOstar:^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            // block 内部逻辑（看下一个函数）
        }];
    } else {
        // 4. 如果字段齐全 → 更新 o36
        [KGShareAppDataManager updateO36:o36];
        self.isFecthingQ36 = NO;
    }
    // 解锁
    [lockObj unlock];
}

// sub_107C0A718 ret= {
//     "KG_H_DEVICE_ID" = 118005780437325208;
//     "KG_IMEI" = f0ba4274f07ab91d5237b5996853acae1ea8e18b;
//     "KG_USERID" = 0;
// }
- (void)setUpOStar {
    OstarService *ostar = [OstarService shareInstance];

    // 1. appVersion
    NSString *appVersion = [StatisticInfo appVersion];
    [ostar setAppVersion:appVersion];

    // 2. channelFlag (渠道)
    NSString *channel = [StatisticInfo channelFlag];
    [ostar setChannelId:channel];

    // 3. udid -> KG_IMEI:f0ba4274f07ab91d5237b5996853acae1ea8e18b
    NSString *udid = [StatisticInfo udid];
    [ostar setUserId:udid forType:@"KG_IMEI"];

    // 4. userId -> KG_USERID
    NSString *userId = [[UserOpBLL shareUserInfo] userID];
    [ostar setUserId:userId forType:@"KG_USERID"];

    // 5. H_DEVICE_ID
    KGSeverShareDeviceIDGen *gen = [TrackerLiteContext setBaseContext];
    NSString *h_device_id = [gen getLocalServerSharedDeviceIDString];
    [ostar setUserId:h_device_id forType:@"KG_H_DEVICE_ID"];

    // 6. AppKey（非常关键，反克隆检测使用）
    [ostar setAppkey:@"0IOS0L946E4OIXHV"];

    // 7. deviceIDMachineName -> JSON -> NSDictionary
    NSString *jsonStr = [self deviceIDMachineName];
    NSDictionary *dict = [NSDictionary dictionaryWithJSONString:jsonStr error:nil];

    // 8. 获取 o16 / o36
    NSString *o16 = [dict stringForKeyKGSafe:@"o16"];
    NSString *o36 = [dict stringForKeyKGSafe:@"o36"];

    // 如果 o36 为空，用默认（从全局结构取的）
    if ([StringTool isEmptyStr:o36]) {
        o36 = stru_10F8E5610;  // 默认 o36
    }

    // 9. 启动 OStar
    [ostar startWithO16:o16 o36:o36 delegate:self];
}


✅-[KGTencentStatistics deviceIDMachineName]
NSString *deviceIDMachineName() {
    //1、先从keychain 读取 kTencentStatic_Qimei
    NSString *keychainQimei = [UICKeyChainStore stringForKey:@"kTencentStatic_Qimei"];

    //2、从NSUserDefaults读取，有就直接返回
    NSString *autoGen = [self getTencentAutoTrackSeverGenUdidBigNumber];
    if (autoGen.length == 0) {
        // autoGen 为空，只能使用 keychain 值
        if (keychainQimei == nil) {
            return nil;
        }
        return [keychainQimei copy];
    }

    // autoGen 有内容
    if (keychainQimei == nil) {
        // keychain 没有 → 使用 autoGen 写入 keychain
        [UICKeyChainStore setString:autoGen forKey:@"kTencentStatic_Qimei"];
        return autoGen;
    }

    // keychain 有值
    // 用 keychain 覆盖 autoGen
    [self setTencentAutoTrackSeverGenUdidBigNumber:keychainQimei];
    return keychainQimei;
}

// 从NSUserDefaults读 
- (id)getTencentAutoTrackSeverGenUdidBigNumber {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    id value = [defaults objectForKeyKGSafe:@"kTencentStatic_Qimei"];
    return value;
}
//写入NSUserDefaults里
- (void)setTencentAutoTrackSeverGenUdidBigNumber:(id)value {
    NSUserDefaults *def = [NSUserDefaults standardUserDefaults];
    [def setObjectKGSafe:value forKey:@"kTencentStatic_Qimei"];
    [def synchronize];
}