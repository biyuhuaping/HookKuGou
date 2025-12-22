  2924 ms  0x116cfa574 KGSafeKit!+[NSJSONSerialization(kgSwizzleGuardSafe) dataWithJSONObjectSafe:options:error:]
0x100ac5588 kugou!+[TGGDTJSONUtil jsonStringFromObject:]
0x100ac57fc kugou!+[TGGDTJSONUtil jsonDataFromObject:]
0x100b3cfc8 kugou!0x684fc8 (0x100684fc8)
0x1ca601850 libdispatch.dylib!_dispatch_call_block_and_release
0x1ca6027c8 libdispatch.dylib!_dispatch_client_callout
0x1ca5d9b2c libdispatch.dylib!_dispatch_queue_override_invoke
0x1ca5e6d48 libdispatch.dylib!_dispatch_root_queue_drain
0x1ca5e7514 libdispatch.dylib!_dispatch_worker_thread2
0x20b07eb14 libsystem_pthread.dylib!_pthread_wqthread


@interface TGGDTSDKServerService : NSObject

+ (void)sendWujiRequest;

@end

@implementation TGGDTSDKServerService

void sendWujiRequest(id self, SEL _cmd) {
    NSNumber *currentTime = [TGGDTTimeUtil currentTime];
    [[self class] setWujiTime:currentTime];
    
    id commonData = [self buildSDKReportCommonData];
    
    if ([GDTSDKPrivateConfig showDebugLog]) {
        if ([GDTSDKPrivateConfig showNSLog]) {
            NSString *filePath = [NSString stringWithUTF8String:"/Volumes/data/workspace/GDTMobSDK/Service/GDTSDKServer/TGGDTSDKServerService.m"];
            NSString *fileName = [filePath lastPathComponent];
            NSString *logMessage = [NSString stringWithFormat:@"无极请求-body：%@", commonData];
            NSLog(@"GDTLog[%@]:%@", fileName, logMessage);
        }
        
        NSString *logMessage = [NSString stringWithFormat:@"无极请求-body：%@", commonData];
        [TGGDTLogger reportSDKGDTlog:logMessage];
    }
    
    NSString *logMessage = [NSString stringWithFormat:@"无极请求-body：%@", commonData];
    [TGGDTLogger outputToAppDeveloperLevel:1 log:logMessage];
    
    NSData *jsonData = [TGGDTJSONUtil jsonDataFromObject:commonData];
    
    sleep(1.0);
    delay(40000);
    
    TGGDTNetClient *netClient = [TGGDTNetClient sharedInstance];
    NSString *url = [self sdkNewServerUrlWithPath:@"updateSetting"];
    id successBlock = [[self class] successBlockFromWUJI];
    id failureBlock = [[self class] failureBlockFromWUJI];
    
    [netClient postURL:url body:jsonData retryTimes:1 enableJSON:YES success:successBlock failure:failureBlock];
}

+ (NSDictionary *)buildSDKReportCommonData {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    
    NSMutableDictionary *appInfo = [NSMutableDictionary dictionary];
    TGGDTDeviceManager *deviceManager = [TGGDTDeviceManager defaultManager];
    [deviceManager collectAppInfo:appInfo];
    
    NSMutableDictionary *deviceInfo = [NSMutableDictionary dictionary];
    deviceManager = [TGGDTDeviceManager defaultManager];
    [deviceManager collectDeviceInfo:deviceInfo];
    
    NSMutableDictionary *sdkInfo = [NSMutableDictionary dictionary];
    deviceManager = [TGGDTDeviceManager defaultManager];
    [deviceManager collectSDKInfo:sdkInfo];
    
    [result gdt_safeSetObject:deviceInfo forKey:@"dev"];
    [result gdt_safeSetObject:sdkInfo forKey:@"sdk"];
    [result gdt_safeSetObject:appInfo forKey:@"app"];
    
    TGGDTSettingManager *settingManager = [TGGDTSettingManager defaultManager];
    NSDictionary *signatureDict = [settingManager signatureDictionary];
    [result gdt_safeSetObject:signatureDict forKey:@"sig"];
    
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        TGGDTInDaUseNotifyDelegate *delegate = [TGGDTInDaUseNotifyDelegate getUseNotifyDelegate];
        NSArray *focusInfo = [TGGDTInDaUseNotifyDelegate getFocusInfo];
        
        if (delegate && [delegate respondsToSelector:@selector(useNotify:)] && [focusInfo count] > 0) {
            NSMutableDictionary *notifyDict = [NSMutableDictionary dictionary];
            TGGDTDeviceManager *deviceManager = [TGGDTDeviceManager defaultManager];
            NSDictionary *settingList = [deviceManager fetchSettinglist];
            NSArray *allKeys = [settingList allKeys];
            
            if ([allKeys count] > 0) {
                for (int i = 0; i < [allKeys count]; i++) {
                    for (int j = 0; j < [focusInfo count]; j++) {
                        NSInteger focusValue = [focusInfo gdtIntAtIndex:j];
                        NSInteger settingKey = [allKeys gdtIntAtIndex:i];
                        
                        if (focusValue == settingKey) {
                            NSString *key = [allKeys objectAtIndexedSubscript:i];
                            TGGDTDeviceManager *deviceManager = [TGGDTDeviceManager defaultManager];
                            NSDictionary *settingList = [deviceManager fetchSettinglist];
                            NSString *value = [settingList gdtStringForKey:key];
                            
                            [notifyDict gdt_safeSetObject:value forKey:key];
                        }
                    }
                }
            }
            
            if ([notifyDict count] > 0) {
                [delegate useNotify:notifyDict];
            }
        }
    });
    
    return result;
}