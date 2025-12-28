- (NSDictionary *)getTangramDeviceInfo {
    // 如果正在获取，直接返回缓存
    if (self.isGettingParam) {
        return self.device;
    }

    self.isGettingParam = YES;

    CFAbsoluteTime startTime = CFAbsoluteTimeGetCurrent();

    // 1. 构建 TGGDTGetDeviceParams
    TGGDTGetDeviceParams *deviceParams = [[TGGDTGetDeviceParams alloc] init];
    [deviceParams setScene:0];

    // 2. 构建 GDTLoadAdParams
    GDTLoadAdParams *loadAdParams = [[GDTLoadAdParams alloc] init];

    // mediaSource
    TMAConfigManager *configMgr = [TMAConfigManager defaultManager];
    id interactiveConfig = [configMgr interactiveAdConfig];
    NSString *mediaSource = [interactiveConfig getMediaSource];
    if (!mediaSource) {
        mediaSource = @""; // stru_10FA56C28
    }
    [loadAdParams setMediaSource:mediaSource];

    // loginType
    id userConfig = [configMgr userConfig];
    NSInteger tmeLoginType = [userConfig loginOpenIdType];
    NSInteger gdtLoginType =
        [self gdtLoginTypeWithTmeLoginType:tmeLoginType];
    [loadAdParams setLoginType:gdtLoginType];

    // loginAppId
    NSString *loginAppId = [userConfig loginAppId];
    [loadAdParams setLoginAppId:loginAppId];

    // loginOpenId
    NSString *loginOpenId = [userConfig loginOpenId];
    [loadAdParams setLoginOpenId:loginOpenId];

    // 3. 绑定 loadAdParams
    [deviceParams setLoadAdParams:loadAdParams];

    // 4. 获取 Tangram 设备信息
    NSDictionary *deviceInfo = [GDTTangramDeviceManager getTangramDeviceInfoWithScene:deviceParams];

    // 5. 缓存结果
    self.device = deviceInfo;
    self.isGettingParam = NO;

    CFAbsoluteTime endTime = CFAbsoluteTimeGetCurrent();

    // 6. 首次上报耗时
    if (!self.isRepored) {
        self.isRepored = YES;

        TMEAdAttaReportModel *model =
            [[TMEAdAttaReportModel alloc] init];
        [model setAction:@"init"];
        [model setSubAction:@"ams"];

        int64_t timeCost =
            (int64_t)((endTime - startTime) * 1000.0);
        [model setTimeCost:timeCost];

        [[TMEAdAttaReport shareReport]
            reportAttaAction:model immediately:NO];
    }

    return deviceInfo;
}
