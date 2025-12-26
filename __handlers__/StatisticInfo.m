
@implementation StatisticInfo

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

@end

          /* TID 0x5c03 */
  3653 ms  stack: 0x102a20fb8 kugou!+[StatisticInfo udid]
0x119cfbbec KGDataChannel!-[KGDataChannel udid]
0x119ce0620 KGDataChannel!-[CSCCCryptMgr genFromServer]
0x119ce0530 KGDataChannel!-[CSCCCryptMgr generateDynamicKey:]
0x119cf4e1c KGDataChannel!__95-[KGCSCChanel(autoTrack) sendPBImmediatelyOutChannelDispather:andDataAppVersion:andDataUserID:]_block_invoke
0x190f8b7a8 libdispatch.dylib!_dispatch_call_block_and_release
0x190f8c780 libdispatch.dylib!_dispatch_client_callout
0x190f676fc libdispatch.dylib!_dispatch_lane_serial_drain$VARIANT$armv81
0x190f681b0 libdispatch.dylib!_dispatch_lane_invoke$VARIANT$armv81
0x190f71f14 libdispatch.dylib!_dispatch_workloop_worker_thread
0x1d4f8abd0 libsystem_pthread.dylib!_pthread_wqthread
  3772 ms  NeeFileCache key: appUdid value: f0ba4274f07ab91d5237b5996853acae1ea8e18b



             /* TID 0x5c03 */
  6660 ms  stack: 0x102a20fb8 kugou!+[StatisticInfo udid]
0x10bb11990 kugou!-[KGUploadLogsDataManager userKey]
0x10bb11a68 kugou!-[KGUploadLogsDataManager getUserIsHitKey]
0x10bb11928 kugou!-[KGUploadLogsDataManager getUserIsHitValue]
0x108864714 kugou!-[KGInternalTestingUserManager isInternalTestingUse]
0x10b84a70c kugou!-[KGTarget_ListenModuleAdapt isInternalTestingUser]
0x10d194d14 kugou!-[KGMediator safePerformAction:target:params:]
0x10d194a08 kugou!-[KGMediator performTarget:action:params:shouldCacheTarget:]
0x10d1bd6d8 kugou!-[KGMediator isInternalTestingUser]
0x102ab73bc kugou!-[KGHttpRequest willStartRequest]
0x106fd3de8 kugou!-[KGHttpRequest synStartWithError:]
0x119cfdb80 KGDataChannel!-[KGProtocolHttp synAccessService:]
0x119ce7a10 KGDataChannel!-[CSCCGenProtocol synAccessService]
0x119ce067c KGDataChannel!-[CSCCCryptMgr genFromServer]
0x119ce0530 KGDataChannel!-[CSCCCryptMgr generateDynamicKey:]
0x119cf4e1c KGDataChannel!__95-[KGCSCChanel(autoTrack) sendPBImmediatelyOutChannelDispather:andDataAppVersion:andDataUserID:]_block_invoke
  7884 ms  NeeFileCache key: appUdid value: f0ba4274f07ab91d5237b5996853acae1ea8e18b