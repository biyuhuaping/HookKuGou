+ (NSString *)udid {
    // 1. 从 NeeFileCache 读取 key = "appUdid"
    id value = [[NeeFileCache sharedInstance] objectForKeyedSubscript:@"appUdid"];

    NSString *result = [NSString stringWithFormat:@"%@", value];
    return result;
}

+ (id)appVersion {
    KGMediator *mediator = [KGMediator shareInstance];
    NSDictionary *versionInfoDic = [mediator versionInfoDic];
    id version = versionInfoDic[@"version"];
    return version;
}

+ (id)channelFlag {
    KGMediator *mediator = [KGMediator shareInstance];

    BOOL isDebug = [mediator getAppIsDebug];

    NSDictionary *versionInfoDic = [mediator versionInfoDic];

    // 5. 根据 Debug/Release 选择不同的 key
    // Debug 环境下：用 @"innerChannel"
    // Release 环境下：用 @"channel"
    NSString *key = isDebug ? @"innerChannel" : @"channel";
    id result = versionInfoDic[key];
    return result;
}
