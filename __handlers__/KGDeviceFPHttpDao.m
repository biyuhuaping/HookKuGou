
@implementation KGDeviceFPHttpDao

// -[KGDeviceFPHttpDao requestDeviceDFIDWith:isSmallPackage:error:]
- (NSDictionary *)requestDeviceDFIDWith:(NSString *)ddfid isSmallPackage:(BOOL)isSmall error:(NSError **)error {
// 这里的 ddfid 并未被使用，可能是之前版本遗留的参数。
    id copiedDdfid = [ddfid copy];

    // Header
    NSMutableDictionary *header = [NSMutableDictionary dictionary];
    header[@"DeviceFP"] = @"UserAgent";

    // 获取安全令牌信息
    NSDictionary *sec = [[UserOpBLL shareUserInfo] securityTokenDict];
    header[@"KG-DEVID"] = sec[@"t2"];
    header[@"KG-CLIENTTIMEMS"] = sec[@"clienttime_ms"];

    // 获取设备指纹信息
    NSDictionary *dfInfo = [[KGDeviceFPManager shareInstance] dfInfo];
    NSMutableDictionary *dfDict = [NSMutableDictionary dictionaryWithDictionary:dfInfo];
    NSString *q36 = [[KGTencentStatistics q36] ?: @"default_q36_value"];
    dfDict[@"q36"] = q36;

    // AES key / iv
    NSString *udid = [StatisticInfo udid];
    NSString *key = [udid substringWithRange:NSMakeRange(0, 16)];
    NSString *iv  = [udid substringWithRange:NSMakeRange(16, 16)];

    NSData *json = [NSJSONSerialization dataWithJSONObject:dfDict options:0 error:nil];
    NSData *aes  = [[KGMediator shareInstance] AES128EncryptWithData:json AndKey:key andIv:iv];
    NSString *base64 = [aes base64EncodedString];

    // RSA
    NSDictionary *rsaDic = @{@"aes": base64};
    NSString *rsa = [[KGMediator shareInstance] kgPlayListRSAEncrypt:[rsaDic JSONString2]];

    NSMutableDictionary *params = [NSMutableDictionary dictionary];
    params[@"userid"] = [[KGMediator shareInstance] kgUserID];
    params[@"platid"] = @2;
    params[@"p"] = rsa;
    params[@"part"] = @(isSmall);

    // 签名，hook
    NSDictionary *signedParams = [KGNetworkTools signFillUrlCustomParameterDictionary:params bodyString:base64 isCdnRequest:NO signature:nil];

    // 创建POST请求信息
    PostMethodInfo *info = [PostMethodInfo new];
    info.urlKey = @"listen.usermodule.risk.r_register_dev";
    info.header = header;
    info.postBody = [base64 dataUsingEncoding:NSUTF8StringEncoding];

    NSData *resp = [self doPostWithPostMethodInfo:info error:error];
    if (!resp) return nil;

    NSData *dec = [[KGMediator shareInstance] AES128DecryptToDateWithKey:key andIv:iv];
    return [NSJSONSerialization JSONObjectWithData:dec options:0 error:nil];
}


@end


/*
-[KGDeviceFPManager dfInfo]
 10703 ms  retval OC object: YYThreadSafeDictionary {
    IDFV = "FDE13E38-C65A-4C5A-B61D-D5C28F5BB290";
    IP = "192.168.159.32";
    acc =     {
        aX = "0.002166748046875";
        aY = "0.010711669921875";
        aZ = "-0.9998321533203125";
        iX = "0.00347900390625";
        iY = "0.0120086669921875";
        iZ = "-0.9960784912109375";
    };
    appCurName = "\U9177\U72d7\U97f3\U4e50";
    appCurVerNum = "20.4.4.19";
    appCurVersion = "20.4.4";
    battery = "96:2";
    brightness = "0.6499999761581421";
    bssid = "";
    call = 1;
    camera = 1;
    cameraF = 1;
    channel = 1009;
    devOrient = 0;
    deviceName = "iPhone 11";
    flash = 1;
    gitVer = ff2ffd9;
    groot = 0;
    gyro =     {
        aX = "-0.01401142310351133";
        aY = "0.006248308345675468";
        aZ = "0.007601993158459663";
        iX = "-0.009621202014386654";
        iY = "0.008848885074257851";
        iZ = "0.006328203249722719";
    };
    gyroscope = 1;
    height = 896;
    localizedModel = iPhone;
    locationState = 0;
    mag =     {
        aX = "101.4808654785156";
        aY = "24.19731140136719";
        aZ = "-249.1030426025391";
        iX = "101.7821044921875";
        iY = "24.64457702636719";
        iZ = "-248.6485595703125";
    };
    memory = "221.8876664201183";
    mic = 1;
    mid = de200408f3f04354795413b01dd77c57d0967c52;
    notif = 1;
    phoneModel = "iPhone 8 Plus";
    photo = 0;
    resolution = "828*1792";
    ssid = "";
    systemName = iOS;
    systemVersion = "15.2";
    uuid = de200408f3f04354795413b01dd77c57d0967c52;
    ver = 20449;
    videoC = 1;
    width = 414;
}

*/