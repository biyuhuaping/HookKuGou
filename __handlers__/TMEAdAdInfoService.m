#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

@interface TMEAdAdInfoService : NSObject
@property (nonatomic, strong) NSNumber *adLastReqTime;
@property (nonatomic, copy) NSString *adReqCookieStr;
@end

@interface TMEAdLoadAdParams : NSObject
@property (nonatomic, assign) NSInteger userType;
@property (nonatomic, copy) NSString *gdtHippyModuleName;
@property (nonatomic, assign) NSInteger adStartPos;
@property (nonatomic, assign) NSInteger adEndPos;
@property (nonatomic, copy) NSArray<NSString *> *exp_id;
@property (nonatomic, copy) NSArray<NSString *> *ams_exp_id;
@property (nonatomic, copy) NSArray<NSString *> *exp_id_v2;
@end

@interface TMAConfigManager : NSObject
+ (instancetype)defaultManager;
- (id)sdkConfig;
@end

@interface TMEAdSDKConfigContentModel : NSObject
@property (nonatomic, assign) BOOL disableAddJsInfo;
@end

@interface TMEAdSDKLogManager : NSObject
+ (instancetype)shareManager;
- (void)logLevel:(NSInteger)level tagInfo:(NSString *)tag logFormat:(NSString *)format, ...;
@end

@interface TMEAdJSONUtil : NSObject
+ (NSString *)jsonStringFromDic:(NSDictionary *)dic;
@end

@interface TMEAdPBHelper : NSObject
+ (void)addPBEncoder:(void *)pb string:(NSString *)string index:(NSInteger)index;
+ (void)addPBEncoder:(void *)pb uint64:(uint64_t)value index:(NSInteger)index;
@end

@interface TMEAdTimeUtil : NSObject
+ (NSTimeInterval)currentTime;
@end

@interface DKDynamicBundleManager : NSObject
+ (instancetype)sharedInstance;
- (id)moduleItemWithName:(NSString *)moduleName;
@end

@interface DKBundleItem : NSObject
@property (nonatomic, copy) NSString *version;
@end

@implementation TMEAdAdInfoService

+ (NSData *)p_handleLiuJinPBReqPlacementId:(NSString *)placementId 
                             loadAdParams:(TMEAdLoadAdParams *)loadAdParams 
                                amsDevice:(NSDictionary *)amsDevice 
                                   reqSeq:(NSString *)reqSeq 
                                reportDic:(NSDictionary *)reportDic {
    
    @autoreleasepool {
        // 1. 初始化PB编码器
        void *pbEncoder = [self createPBEncoder];
        
        // 2. 设置基本字段
        int index = 1;
        [TMEAdPBHelper addPBEncoder:pbEncoder string:placementId index:index++];
        
        // 3. 设置用户类型
        [TMEAdPBHelper addPBEncoder:pbEncoder uint64:loadAdParams.userType index:index++];
        
        // 4. 设置广告请求cookie
        NSString *cookieStr = [self adReqCookieStr];
        [TMEAdPBHelper addPBEncoder:pbEncoder string:cookieStr index:index++];
        
        // 5. 处理设备扩展信息
        NSMutableDictionary *deviceExtInfo = [self processDeviceExtInfoWithParams:loadAdParams 
                                                                       amsDevice:amsDevice];
        
        // 6. 构建设备信息JSON
        NSDictionary *deviceInfo = @{
            @"adStartPos": @(loadAdParams.adStartPos),
            @"adEndPos": @(loadAdParams.adEndPos),
            @"device_ext": deviceExtInfo ?: @{}
        };
        
        NSString *deviceInfoJSON = [TMEAdJSONUtil jsonStringFromDic:deviceInfo];
        [TMEAdPBHelper addPBEncoder:pbEncoder string:deviceInfoJSON index:index++];
        
        // 7. 设置请求序列号
        [TMEAdPBHelper addPBEncoder:pbEncoder string:reqSeq index:index++];
        
        // 8. 处理实验ID数组
        [self addExpIDsToPBEncoder:pbEncoder ids:loadAdParams.exp_id index:index++];
        [self addExpIDsToPBEncoder:pbEncoder ids:loadAdParams.ams_exp_id index:index++];
        [self addExpIDsToPBEncoder:pbEncoder ids:loadAdParams.exp_id_v2 index:index++];
        
        // 9. 添加手机信息和用户信息
        [self handleLiuJinPBReqPhoneInfo:pbEncoder device:amsDevice reportDic:reportDic];
        [self handleLiuJinPBReqUserInfo:pbEncoder loadAdParams:loadAdParams reportDic:reportDic];
        [self handleLiuJinPBReqReqInfo:pbEncoder placementId:placementId loadAdParams:loadAdParams];
        
        // 10. 生成CID
        NSTimeInterval currentTime = [TMEAdTimeUtil currentTime];
        NSString *cid = [self getCidWithTime:currentTime seq:reqSeq device:amsDevice];
        [TMEAdPBHelper addPBEncoder:pbEncoder string:cid index:index++];
        
        // 11. 添加时间戳
        [TMEAdPBHelper addPBEncoder:pbEncoder uint64:(uint64_t)currentTime index:index++];
        
        // 12. 添加SDK配置更新时间
        NSArray<NSNumber *> *sdkConfigUpdateTimes = [self getSDKConfigUpdateTime];
        for (NSNumber *timestamp in sdkConfigUpdateTimes) {
            [TMEAdPBHelper addPBEncoder:pbEncoder uint64:[timestamp unsignedLongValue] index:index];
        }
        
        // 13. 序列化PB数据
        NSData *pbData = [self serializePBEncoder:pbEncoder];
        
        // 14. 清理资源
        [self releasePBEncoder:pbEncoder];
        
        return pbData;
    }
}

#pragma mark - 设备扩展信息处理

+ (NSMutableDictionary *)processDeviceExtInfoWithParams:(TMEAdLoadAdParams *)params 
                                              amsDevice:(NSDictionary *)amsDevice {
    NSMutableDictionary *deviceExtInfo = [NSMutableDictionary dictionary];
    
    if (amsDevice) {
        [deviceExtInfo addEntriesFromDictionary:amsDevice];
    }
    
    // 添加Hippy模块信息
    NSString *hippyModuleName = params.gdtHippyModuleName;
    if (hippyModuleName && hippyModuleName.length > 0) {
        deviceExtInfo[@"module_name"] = hippyModuleName;
        
        // 尝试获取Hippy模块的版本信息
        NSString *jsBundleInfo = [self getJSBundleInfoForModule:hippyModuleName];
        if (jsBundleInfo) {
            deviceExtInfo[@"jsbundle_info"] = jsBundleInfo;
        }
    }
    
    return deviceExtInfo;
}

+ (NSString *)getJSBundleInfoForModule:(NSString *)moduleName {
    @try {
        // 尝试通过反射获取动态Bundle管理器
        Class bundleManagerClass = NSClassFromString(@"DKDynamicBundleManager");
        if (!bundleManagerClass) {
            return nil;
        }
        
        SEL sharedInstanceSel = NSSelectorFromString(@"sharedInstance");
        if (![bundleManagerClass respondsToSelector:sharedInstanceSel]) {
            return nil;
        }
        
        id bundleManager = ((id (*)(Class, SEL))objc_msgSend)(bundleManagerClass, sharedInstanceSel);
        if (!bundleManager) {
            return nil;
        }
        
        SEL moduleItemSel = NSSelectorFromString(@"moduleItemWithName:");
        if (![bundleManager respondsToSelector:moduleItemSel]) {
            return nil;
        }
        
        id bundleItem = ((id (*)(id, SEL, NSString *))objc_msgSend)(bundleManager, moduleItemSel, moduleName);
        if (!bundleItem) {
            return nil;
        }
        
        SEL versionSel = NSSelectorFromString(@"version");
        if (![bundleItem respondsToSelector:versionSel]) {
            return nil;
        }
        
        NSString *version = ((id (*)(id, SEL))objc_msgSend)(bundleItem, versionSel);
        if (![version isKindOfClass:[NSString class]]) {
            return nil;
        }
        
        // 构建JSON字符串
        NSString *jsBundleInfo = [NSString stringWithFormat:@"{\"%@\":\"%@\"}", moduleName, version];
        
        // 记录日志
        TMEAdSDKLogManager *logManager = [TMEAdSDKLogManager shareManager];
        [logManager logLevel:4 tagInfo:@"SERVICE" logFormat:@"广告请求添加jsbundle_info成功"];
        
        return jsBundleInfo;
    } @catch (NSException *exception) {
        return nil;
    }
}

#pragma mark - 实验ID处理

+ (void)addExpIDsToPBEncoder:(void *)pbEncoder ids:(NSArray<NSString *> *)expIds index:(NSInteger)index {
    if (!expIds || expIds.count == 0) {
        return;
    }
    
    for (NSString *expId in expIds) {
        if ([expId isKindOfClass:[NSString class]] && expId.length > 0) {
            [TMEAdPBHelper addPBEncoder:pbEncoder string:expId index:index];
        }
    }
}

#pragma mark - CID生成

+ (NSString *)getCidWithTime:(NSTimeInterval)time seq:(NSString *)seq device:(NSDictionary *)device {
    // 使用时间戳、序列号和设备信息生成CID
    NSString *input = [NSString stringWithFormat:@"%.0f_%@_%@", time, seq, device[@"device_id"] ?: @""];
    
    const char *inputStr = [input UTF8String];
    unsigned char hash[CC_MD5_DIGEST_LENGTH];
    CC_MD5(inputStr, (CC_LONG)strlen(inputStr), hash);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", hash[i]];
    }
    
    return [output uppercaseString];
}

#pragma mark - PB编码器管理

+ (void *)createPBEncoder {
    // 创建PB编码器
    return malloc(1024); // 简化示例
}

+ (NSData *)serializePBEncoder:(void *)pbEncoder {
    // 序列化PB数据
    return [NSData data];
}

+ (void)releasePBEncoder:(void *)pbEncoder {
    // 释放PB编码器
    if (pbEncoder) {
        free(pbEncoder);
    }
}

#pragma mark - 占位方法

+ (void)handleLiuJinPBReqPhoneInfo:(void *)pbEncoder device:(NSDictionary *)device reportDic:(NSDictionary *)reportDic {
    // 处理手机信息
}

+ (void)handleLiuJinPBReqUserInfo:(void *)pbEncoder loadAdParams:(TMEAdLoadAdParams *)params reportDic:(NSDictionary *)reportDic {
    // 处理用户信息
}

+ (void)handleLiuJinPBReqReqInfo:(void *)pbEncoder placementId:(NSString *)placementId loadAdParams:(TMEAdLoadAdParams *)params {
    // 处理请求信息
}

+ (NSArray<NSNumber *> *)getSDKConfigUpdateTime {
    // 获取SDK配置更新时间
    return @[];
}


// +[TMEAdAdInfoService requestPBAdInfoFromLiuJinWithReqParams:complateHandle:netRspHandle:failure:]
+ (void)requestPBAdInfoFromLiuJinWithReqParams:(TMEAdInfoReqParamsStruct *)reqParams
                                 complateHandle:(void (^)(id response))completion
                                   netRspHandle:(void (^)(id response))netResponse
                                        failure:(void (^)(NSError *error))failure {
    
    @autoreleasepool {
        // 1. 参数解包
        NSString *placementId = reqParams->placementId;
        NSString *realityPlacement = reqParams->realityPlacement;
        TMEAdLoadAdParams *loadAdParams = reqParams->loadAdParams;
        BOOL isVar4 = reqParams->var4;
        BOOL isVar3 = reqParams->var3;
        NSTimeInterval var7 = reqParams->var7;
        NSTimeInterval var5 = reqParams->var5;
        BOOL shouldCompress = reqParams->var9;
        
        // 2. 获取包名资源
        TMEAdDownloadTaskManager *taskManager = [TMEAdDownloadTaskManager sharedInstance];
        NSString *pkgNameResources = [taskManager getTodayAppNameWithPlacement:realityPlacement];
        
        if (pkgNameResources) {
            NSMutableDictionary *paramsDict = [loadAdParams.dictionary mutableCopy];
            paramsDict[@"pkg_name_resources"] = pkgNameResources;
            [loadAdParams setDictionary:paramsDict];
            
            [[TMEAdSDKLogManager shareManager] logLevel:4 
                                                tagInfo:@"DOWNLOAD" 
                                             logFormat:@"getTodayAppNameWithPlacement pkg_name_resources appName = %@", pkgNameResources];
        }
        
        // 3. 检查placementId是否有效
        if (![placementId isKindOfClass:[NSString class]] || placementId.length == 0) {
            [[TMEAdSDKLogManager shareManager] logLevel:1 
                                                tagInfo:@"SERVICE" 
                                             logFormat:@"ad request-PB-pod is nil"];
            return;
        }
        
        // 4. 记录请求开始
        [[TMEAdSDKLogManager shareManager] logLevel:4 
                                            tagInfo:@"SERVICE" 
                                         logFormat:@"ad request-PB-start-pid=%@", placementId];
        
        [self doRequestReportToLiuJinPid:placementId cause:nil loadParams:loadAdParams];
        
        // 5. 获取设备信息和请求序列号
        NSDictionary *deviceInfo = [[TMEAdGDTParamManager shareInstance] getTangramDeviceInfo];
        NSString *reqSeq = [self getReqSeq];
        NSTimeInterval currentTime = [TMEAdTimeUtil currentTime];
        
        // 6. 创建上报模型
        TMEAdAttaReportModel *attaReport = [[TMEAdAttaReportModel alloc] init];
        attaReport.action = @"request";
        attaReport.subAction = shouldCompress ? @"zipPB" : @"PB";
        attaReport.reqSeq = reqSeq;
        attaReport.podId = placementId;
        attaReport.reqProtocol = isVar4 ? 2 : isVar3;
        attaReport.times = [self getHttpStrategyReportValue];
        
        [[TMEAdAttaReport shareReport] reportAttaAction:attaReport immediately:NO];
        
        // 7. 创建Link上报模型
        TMEAdLinkAttaReportModel *linkAttaReport = [TMEAdLinkAttaReportModel modelWithAdParams:loadAdParams];
        linkAttaReport.traceid = reqSeq;
        linkAttaReport.channelId = placementId;
        
        // 8. 准备请求参数
        NSMutableDictionary *requestParams = [NSMutableDictionary dictionary];
        NSData *pbData = [self p_handleLiuJinPBReqPlacementId:placementId 
                                                loadAdParams:loadAdParams 
                                                   amsDevice:deviceInfo 
                                                      reqSeq:reqSeq 
                                                   reportDic:requestParams];
        
        if (shouldCompress) {
            pbData = [TMEAdCommonUtil gzipDeflate:pbData];
        }
        
        // 9. 检查请求数据是否有效
        if (!pbData || pbData.length == 0) {
            [[TMEAdSDKLogManager shareManager] logLevel:1 
                                                tagInfo:@"SERVICE" 
                                             logFormat:@"ad request-PB-setup params fail-pid=%@", placementId];
            
            attaReport.action = @"requestFail";
            attaReport.subAction = @"pbReqFail";
            [[TMEAdAttaReport shareReport] reportAttaAction:attaReport immediately:NO];
            
            [[TMEAdLinkAttaReport shareReport] reportAttaAction:linkAttaReport retCode:4001110];
            return;
        }
        
        // 10. 确定实际广告位
        NSString *realityPlacementToUse = realityPlacement;
        if (!realityPlacementToUse || realityPlacementToUse.length == 0) {
            realityPlacementToUse = placementId;
        }
        
        // 11. 检查是否允许重复请求
        TMAConfigManager *configManager = [TMAConfigManager defaultManager];
        id adConfig = [configManager adConfig];
        id adConfigModel = [adConfig getAdConfigModelWithPosId:realityPlacementToUse];
        BOOL allowRepeatRequest = [[adConfigModel valueForKey:@"allowRepeatRequest"] boolValue];
        
        [[TMEAdSDKLogManager shareManager] logLevel:4 
                                            tagInfo:@"SERVICE" 
                                         logFormat:@"ad request-PB-allowRepeatRequest=%d,realityPlacement=%@-pid=%@", 
                                                 allowRepeatRequest, realityPlacementToUse, placementId];
        
        // 12. 检查重复请求锁
        if (!allowRepeatRequest) {
            @synchronized(_gRealityPlacementLock) {
                NSNumber *existingRequest = _gRealityPlacementLock[realityPlacementToUse];
                if (existingRequest && [existingRequest boolValue]) {
                    [[TMEAdSDKLogManager shareManager] logLevel:1 
                                                        tagInfo:@"SERVICE" 
                                                     logFormat:@"ad request-PB-same pid is requesting-pid=%@-rewardSourceID=%ld", 
                                                             realityPlacementToUse, [loadAdParams.rewardSourceID integerValue]];
                    
                    if (failure) {
                        NSError *error = [NSError errorWithDomain:@"timeout" 
                                                             code:4001113 
                                                         userInfo:nil];
                        failure(error);
                    }
                    
                    attaReport.action = @"requestFail";
                    attaReport.reqSeq = reqSeq;
                    attaReport.podId = realityPlacementToUse;
                    attaReport.reqProtocol = isVar4 ? 2 : isVar3;
                    attaReport.code = @"4001113";
                    [[TMEAdAttaReport shareReport] reportAttaAction:attaReport immediately:NO];
                    
                    return;
                }
                
                // 设置请求锁
                _gRealityPlacementLock[realityPlacementToUse] = @YES;
            }
        }
        
        // 13. 上报隐私数据
        [[TMAPrivacyReportManager defaultManager] addReportWithSource:1 data:requestParams];
        
        // 14. 发起网络请求
        TMEAdNetworkingManager *networkingManager = [TMEAdNetworkingManager sharedInstance];
        
        // 请求Block
        void (^requestBlock)(void) = ^{
            // 发送PB数据
            NSLog(@"Sending PB request data, length: %lu", (unsigned long)pbData.length);
        };
        
        // 响应Block
        void (^responseBlock)(id response) = ^(id response) {
            // 清理请求锁
            if (!allowRepeatRequest) {
                @synchronized(_gRealityPlacementLock) {
                    [_gRealityPlacementLock removeObjectForKey:realityPlacementToUse];
                }
            }
            
            if (netResponse) {
                netResponse(response);
            }
            
            if (completion) {
                completion(response);
            }
        };
        
        // 事件Block
        void (^eventBlock)(NSError *error) = ^(NSError *error) {
            // 清理请求锁
            if (!allowRepeatRequest) {
                @synchronized(_gRealityPlacementLock) {
                    [_gRealityPlacementLock removeObjectForKey:realityPlacementToUse];
                }
            }
            
            if (failure) {
                failure(error);
            }
        };
        
        [networkingManager startRequestBlock:requestBlock 
                              responseBlock:responseBlock 
                                 eventBlock:eventBlock];
        
        // 15. 处理微信Universal Link
        NSString *wxUniversalLink = loadAdParams.wxUniversalLink;
        if (wxUniversalLink && wxUniversalLink.length > 0) {
            [TMEAdDeviceUtil setWXUL:wxUniversalLink];
        }
    }
}

#pragma mark - 辅助方法

+ (NSString *)getReqSeq {
    static NSUInteger seqCounter = 0;
    @synchronized(self) {
        seqCounter++;
        _currentReqSeq = [NSString stringWithFormat:@"%lu_%.0f", 
                         (unsigned long)seqCounter, 
                         [[NSDate date] timeIntervalSince1970] * 1000];
        return _currentReqSeq;
    }
}

+ (void)doRequestReportToLiuJinPid:(NSString *)pid cause:(NSString *)cause loadParams:(TMEAdLoadAdParams *)params {
    // 上报逻辑
    [[TMEAdSDKLogManager shareManager] logLevel:4  tagInfo:@"SERVICE"  logFormat:@"Request report to LiuJin, pid: %@, cause: %@", pid, cause ?: @"normal"];
}

+ (id)getHttpStrategyReportValue {
    // 获取HTTP策略上报值
    return @(1);
}



+ (NSDictionary *)liujin_AdInfoParamsChannelId:(id)cid loadAdParams:(TMEAdLoadParams *)params customReqParam:(NSDictionary *)custom {

    NSMutableDictionary *req = [NSMutableDictionary dictionary];

    // device info
    NSDictionary *deviceInfo = [[TMEAdGDTParamManager shareInstance] getTangramDeviceInfo] ?: @{};
    NSMutableDictionary *deviceDict = [deviceInfo mutableCopy];

    // hippy module info
    if (params.gdtHippyModuleName.length && deviceDict.count) {
        NSMutableDictionary *ext = [[deviceDict[@"device_ext"] ?: @{} mutableCopy];

        ext[@"module_name"] = params.gdtHippyModuleName;

        if (!ext[@"jsbundle_info"] &&
            ![TMAConfigManager.defaultManager.sdkConfig disableAddJsInfo]) {

            // 动态 bundle version
            NSString *version = ...;
            if (version) {
                ext[@"jsbundle_info"] = [NSString stringWithFormat: @"{\"%@\":\"%@\"}", params.gdtHippyModuleName, version];
            }
        }
        deviceDict[@"device_ext"] = [ext copy];
    }

    // user / phone
    req[@"user_info"] = [self liujin_AdReqUserWithAdParams:params];
    req[@"msg_phone_info"] = [self liujin_AdRepPhoneInfoWithAMSInfo:deviceInfo];
    req[@"last_pull_time"] = @(self.adLastReqTime);

    // ad_user_info
    NSDictionary *adUser = @{
        @"adStartPos": @(params.adStartPos),
        @"adEndPos": @(params.adEndPos),
        @"device_info": deviceDict
    };
    req[@"ad_user_info"] = [TMEAdJSONUtil jsonStringFromDic:adUser];

    // experiments
    req[@"experimentId"] = params.exp_id ?: @[];
    req[@"new_experimentId"] = params.exp_id_v2 ?: @[];
    req[@"ams_sdk_experiment_id"] = params.ams_exp_id ?: @[];

    // misc
    req[@"cookie"] = self.adReqCookieStr;
    req[@"seq"] = [self getReqSeq];
    req[@"user_type"] = @(params.userType);

    long long now = [TMEAdTimeUtil currentTime];
    req[@"time"] = @(now);
    req[@"cid"] = [self getCid:now seq:req[@"seq"] device:deviceInfo];
    req[@"sdk_conf_time"] = [self getSDKConfigUpdateTime];

    if (custom) {
        req[@"msg_ad_req_info"] = custom;
    }

    return [req copy];
}


@end