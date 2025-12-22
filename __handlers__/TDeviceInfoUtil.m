👉 NSData -> JSON 出参:{
    q16 = fae0c6104adffedfd37614e500001de19917;
    q36 = fae0c6104adffedfd37614e500001de19917;
}
0x11bf4a530 KGSafeKit!+[NSJSONSerialization JSONObjectWithData:options:error:]
0x1118e04e4 kugou!-[TDMQimeiContent initWithQimeiJson:]
0x1118e64b8 kugou!-[TDMQimeiHandler qimeiContent]
0x1118e09e4 kugou!-[TDMQimeiService getQimei]
0x11d58c644 TDataMaster!-[TDeviceInfoUtil GetQIMEI:] //fae0c6104adffedfd37614e500001de19917
0x11d5c7c88 TDataMaster!TDM::TDeviceInfoCollect::GetQIMEI()
0x11d581f4c TDataMaster!TDM::TDeviceInfoHolder::CollectStringDeviceInfo(tdm_tp_stl_c::tdm_string const&, TDM::DeviceInfo<tdm_tp_stl_c::tdm_string>*)
0x11d5821f4 TDataMaster!TDM::TDeviceInfoHolder::CollectAllDeviceInfoFromSystem()
0x11d5815f4 TDataMaster!TDM::TDeviceInfoHolder::GetStringDeviceInfo(char const*, TDM::DeviceInfo<tdm_tp_stl_c::tdm_string>*)
0x11d585ce4 TDataMaster!TDM::TDeviceInfoHolder::IsAsyncDeviceCollectComplete()
0x11d593e94 TDataMaster!TDM::TDMEventQueue::SwapEventToReportQueue()
0x11d5a3d74 TDataMaster!TDM::TDataMasterReporter::ProcessSingleThread(void*)
0x11d5a34d0 TDataMaster!TDM::TDataMasterReporter::ProcessThread(void*)
0x20b080060 libsystem_pthread.dylib!_pthread_start



@interface TDMQimeiService : NSObject
@property (nonatomic, strong) NSString *cachedQimei;
@property (nonatomic, strong) TDMQimeiService *qimeiService;
@property (nonatomic, strong) TDMQimeiHandler *handler;
@end

@implementation TDMQimeiService

- (NSString *)GetQIMEI:(BOOL)forceRefresh {
    TDM::CCritical lock(&_mutex);
    
    if (_cachedQimei && _cachedQimei.length > 0) {
        return _cachedQimei;
    }
    
    TDMQimeiService *qimeiServ = [self TDMGetQimeiObject:forceRefresh];
    SEL sel = NSSelectorFromString(@"Getqimei");
    if (!qimeiServ || ![qimeiServ respondsToSelector:sel]) {
        NSLog(@"can't get qimei sdk");
        return @"Disable";
    }
    
    id qimeiResult = [qimeiServ performSelector:sel];
    if (!qimeiResult) {
        return nil;
    }
    
    NSString *qimeiOld = [qimeiResult valueForKey:@"qimeiOld"];
    NSString *qimei = [NSString stringWithFormat:@"%@", qimeiOld];
    
    if (qimei && ![qimei isEqualToString:@"(null)"] && [qimei length] > 0) {
        NSLog(@"qimei16 : %@", qimei);
        _cachedQimei = qimei;
    }
    
    return qimei;
}

- (TDMQimeiService *)TDMGetQimeiObject:(BOOL)forceRefresh {
    TDM::CCritical lock(&_mutex);
    
    if (_qimeiService) {
        return _qimeiService;
    }
    
    lock.~CCritical();
    
    Class serviceClass = NSClassFromString(@"TDMQimeiService");
    if (!serviceClass) {
        NSLog(@"get qimei service class fail");
        TDM::CCritical lock2(&_mutex);
        return _qimeiService;
    }
    
    id cachedService = nil;
    {
        TDM::CCritical lock2(&_mutex);
        cachedService = _qimeiService;
    }
    
    if (cachedService) {
        TDM::CCritical lock3(&_mutex);
        return _qimeiService;
    }
    
    NSMethodSignature *signature = [serviceClass methodSignatureForSelector:NSSelectorFromString(@"serviceWithAppkey:")];
    if (!signature) {
        NSLog(@"set qimei key signature is nil");
        TDM::CCritical lock2(&_mutex);
        return _qimeiService;
    }
    
    NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
    [invocation setTarget:serviceClass];
    [invocation setSelector:NSSelectorFromString(@"serviceWithAppkey:")];
    
    NSString *appkey = @"000001ZG9U3KPI1Y";
    [invocation setArgument:&appkey atIndex:2];
    [invocation invoke];
    
    id service = nil;
    if ([signature methodReturnLength] > 0) {
        [invocation getReturnValue:&service];
    }
    
    if (!service) {
        return nil;
    }
    
    {
        TDM::CCritical lock2(&_mutex);
        _qimeiService = service;
    }
    
    Class configClass = NSClassFromString(@"TDMQimeiConfig");
    if (configClass) {
        id config = [[configClass alloc] init];
        
        NSString *address = [self GetQIMEIAddress];
        if (address && [address length] > 0) {
            [config setValue:address forKey:@"domain"];
        }
        
        if ([service respondsToSelector:NSSelectorFromString(@"setconfig:")]) {
            [service performSelector:NSSelectorFromString(@"setconfig:") withObject:config];
        }
    }
    
    if ([service respondsToSelector:NSSelectorFromString(@"setappversion:")]) {
        [service performSelector:NSSelectorFromString(@"setappversion:") withObject:@"1.24.007.1982"];
    }
    
    if (forceRefresh && [service respondsToSelector:NSSelectorFromString(@"setdebugmode:")]) {
        NSNumber *debugMode = [NSNumber numberWithBool:YES];
        [service performSelector:NSSelectorFromString(@"setdebugmode:") withObject:debugMode];
    }
    
    if ([service respondsToSelector:NSSelectorFromString(@"start:")]) {
        [service performSelector:NSSelectorFromString(@"start:") withObject:nil];
    }
    
    if ([service respondsToSelector:NSSelectorFromString(@"sdkversion")]) {
        id version = [service performSelector:NSSelectorFromString(@"sdkversion")];
        if (version && [version isKindOfClass:[NSString class]]) {
            NSLog(@"qimei version -> %@", version);
        }
    }
    
    TDM::CCritical lock3(&_mutex);
    return _qimeiService;
}