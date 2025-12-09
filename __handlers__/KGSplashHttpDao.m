#import <Foundation/Foundation.h>

// 前置声明依赖类
@class KGConfigEntity, KGTencentStatistics, KGNetworkTools, PostMethodInfo, SplashBLL, KGSplashModel, KGAdvertManager, BaseError;

@interface KGSplashHttpDao : NSObject
- (KGSplashModel *)requestRealTimeSplashWithRequestId:(NSString *)requestId
                                        downloadAds:(id)downloadAds
                                      isStartSplash:(BOOL)isStartSplash
                                        customParam:(id)customParam
                                             error:(NSError **)error;
@end

@implementation KGSplashHttpDao

- (KGSplashModel *)requestRealTimeSplashWithRequestId:(NSString *)requestId
                                        downloadAds:(id)downloadAds
                                      isStartSplash:(BOOL)isStartSplash
                                        customParam:(id)customParam
                                             error:(NSError **)error {
    // ===== 1. 初始化请求参数字典 =====
    // 获取公共参数 + 广告信息参数
    NSMutableDictionary *requestParams = [self getCommonDictParam:downloadAds];
    
    // 设置启动页类型（取反 isStartSplash）
    NSNumber *splashType = [NSNumber numberWithInt:!isStartSplash];
    [requestParams setObjectKGSafe:splashType forKey:@"splash_type"];
    
    // 合并自定义参数
    if (customParam) {
        [requestParams addEntriesFromDictionary:customParam];
    }
    
    // ===== 2. 处理首次启动标记 =====
    NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
    NSDate *firstBootDate = [userDefaults objectForKeyKGSafe:@"kSplashRequestFirstBootKey"];
    BOOL isTodayFirstBoot = [firstBootDate isToday];
    NSNumber *todayFirstBoot = [NSNumber numberWithInt:!isTodayFirstBoot];
    [requestParams setObjectKGSafe:todayFirstBoot forKey:@"today_first_boot"];
    
    // 更新首次启动时间为当前时间
    [userDefaults setObjectKGSafe:[NSDate date] forKey:@"kSplashRequestFirstBootKey"];
    [userDefaults synchronize];
    
    // ===== 3. 配置全局校验参数 =====
    KGConfigEntity *config = [KGConfigEntity instance];
    NSNumber *globalInChkNum = [config numberOfKey:@"listen.switchparam.global_in_chk"];
    BOOL globalInChk = globalInChkNum ? [globalInChkNum boolValue] : YES;
    [requestParams setObjectKGSafe:[NSNumber numberWithInt:globalInChk] forKey:@"global_in_chk"];
    
    // ===== 4. 拼接统计参数（q36） =====
    KGTencentStatistics *stat = [KGTencentStatistics sharedInstance];
    NSString *q36Value = [stat q36] ?: @"";
    NSDictionary *q36Dict = @{@"q36": q36Value};
    [requestParams addEntriesFromDictionary:q36Dict];
    
    // ===== 5. 测试参数处理 =====
    [self handleParamsForTest:requestParams];
    
    // ===== 6. 生成请求签名 & 拼接 URL =====
    NSString *paramsJSON = [requestParams JSONString2];
    KGNetworkTools *networkTools = [KGNetworkTools sharedInstance];
    NSString *filledUrl = [networkTools signFillUrlCustomParameterDictionary:q36Dict
                                                               bodyString:paramsJSON
                                                            isCdnRequest:NO
                                                               signature:nil];
    
    // ===== 7. 构建 POST 请求信息 =====
    PostMethodInfo *postInfo = [[PostMethodInfo alloc] init];
    [postInfo setUrlKey:@"listen.admodule.mobile.splash_sort_v4"];
    [postInfo setReturnDataType:0]; // 0 = JSON 类型
    [postInfo setAskWithOnlyWifi:NO]; // 非仅 WiFi 请求
    
    // 设置请求体（JSON 数据）
    NSData *postBody = [requestParams JSONData2];
    [postInfo setPostBody:postBody];
    
    // 配置网络请求方式（是否使用 KG 自有网络库）
    NSString *networkSwitch = [config stringOfKey:@"listen.switchparam.lauch_ad_network"];
    BOOL useKGNetwork = [networkSwitch boolValue];
    [postInfo setUseKGNetwork:useKGNetwork];
    
    // 拼接填充 URL（若有）
    if (filledUrl.length > 0) {
        [postInfo setFillUrl:filledUrl];
    }
    
    // ===== 8. 构建请求头 =====
    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    SplashBLL *splashBLL = [SplashBLL defaultInstance];
    NSString *webUA = [splashBLL webUA];
    [headers setObjectKGSafe:webUA forKey:@"KG-UA"];
    [headers setObjectKGSafe:requestId forKey:@"AD-REQUESTID"];
    [postInfo setHeader:headers];
    
    // ===== 9. 执行 POST 请求 =====
    NSDictionary *responseDict = [self doPostWithPostMethodInfo:postInfo AndError:error];
    if (!responseDict) {
        return nil;
    }
    
    // ===== 10. 解析响应结果 =====
    // 解析状态码 & 错误码
    NSNumber *statusNum = [responseDict kg_numberForKey:@"status"];
    NSInteger status = [statusNum asInteger];
    NSNumber *errorCodeNum = [responseDict kg_numberForKey:@"error_code"];
    NSInteger errorCode = [errorCodeNum asInteger];
    
    // 解析核心数据 & 配置
    NSDictionary *dataDict = [responseDict kg_dictionaryForKey:@"data"];
    NSDictionary *configDict = [dataDict kg_dictionaryForKey:@"config"];
    
    // 更新全局校验状态
    KGAdvertManager *adManager = [KGAdvertManager sharedInstance];
    NSNumber *globalInChkConfig = [configDict numberForKeyKGSafe:@"global_in_chk"];
    BOOL newGlobalInChk = globalInChkConfig ? [globalInChkConfig boolValue] : NO;
    [adManager updateRTGlobalInChk:newGlobalInChk];
    
    // ===== 11. 状态码判断 & 模型转换 =====
    KGSplashModel *splashModel = nil;
    if (status == 1) {
        // 成功：转换为启动页模型
        splashModel = [KGSplashModel convetToKGSplashModel:responseDict isStartSplash:isStartSplash];
        
        // 标记服务器是否适配广告
        BOOL hasAd = [splashModel hasRecommendAds] || [splashModel showAdIds].count > 0;
        [userDefaults setObject:hasAd ? @"1" : @"0" forKey:@"KGSplashADSeverISFitAdForClient"];
        [userDefaults synchronize];
    } else {
        // 失败：处理错误信息
        if (dataDict.allKeys.containsObject:@"ads") {
            // 含广告字段但状态异常，生成特定错误
            BaseError *baseError = [[BaseError alloc] initWithDomain:[_kKGErrorDomainTypeTransaction copy]
                                                              code:0x802CA
                                                          userInfo:nil];
            if (error) *error = (NSError *)baseError;
        } else {
            // 生成服务器错误码对应的错误
            BaseError *baseError = [BaseError createErrorWithServerErrorCode:errorCode + 1000 errorMsg:nil];
            if (error) *error = (NSError *)baseError;
        }
        
        // 标记无适配广告
        [userDefaults setObject:@"0" forKey:@"KGSplashADSeverISFitAdForClient"];
        [userDefaults synchronize];
        
        // 转换为模型（兼容无广告场景）
        splashModel = [KGSplashModel convetToKGSplashModel:responseDict isStartSplash:isStartSplash];
    }
    
    // ===== 12. 存储公网 IP（若有） =====
    NSString *publicIP = [dataDict stringForKeyKGSafe:@"ip"];
    if (publicIP) {
        [splashBLL storePublicIP:publicIP];
    }
    
    return splashModel;
}

- (KGSplashModel *)requestSplashList:(NSInteger)splashType 
                       downloadAds:(id)downloadAds 
                       customParam:(NSDictionary *)customParam 
                             Error:(NSError **)error {
    // ===== 1. 构建基础请求参数 =====
    // 获取公共参数（含广告信息）
    NSMutableDictionary *requestParams = [self getCommonDictParam:downloadAds];
    
    // 设置启动页类型（splash_type）
    if (splashType != 1) {
        NSNumber *splashTypeNum = [NSNumber numberWithInteger:splashType];
        [requestParams setObjectKGSafe:splashTypeNum forKey:@"splash_type"];
    }
    
    // 合并自定义参数
    if (customParam) {
        [requestParams addEntriesFromDictionary:customParam];
    }
    
    // ===== 2. 补充腾讯统计 q36 参数 =====
    // 获取 KGTencentStatistics 单例 & q36 值
    KGTencentStatistics *stat = [KGTencentStatistics sharedInstance];
    NSString *q36Value = [stat q36] ?: @"";
    // 构建 q36 参数字典
    NSDictionary *q36Dict = @{@"q36": q36Value};
    [requestParams addEntriesFromDictionary:q36Dict];
    
    // ===== 3. 生成请求签名 & 拼接 URL =====
    // 转换参数为 JSON 字符串
    NSString *paramsJSON = [requestParams JSONString2];
    // 签名并填充 URL（非CDN请求，无自定义签名）
    KGNetworkTools *networkTools = [KGNetworkTools sharedInstance];
    NSString *filledUrl = [networkTools signFillUrlCustomParameterDictionary:q36Dict
                                                               bodyString:paramsJSON
                                                            isCdnRequest:NO
                                                               signature:nil];
    
    // ===== 4. 构建 POST 请求配置 =====
    PostMethodInfo *postInfo = [[PostMethodInfo alloc] init];
    // 设置请求 URL 密钥
    [postInfo setUrlKey:@"listen.admodule.mobile.splash_v4"];
    // 设置返回数据类型为 JSON（0 = JSON）
    [postInfo setReturnDataType:0];
    // 非仅 WiFi 环境请求
    [postInfo setAskWithOnlyWifi:NO];
    // 设置请求体（JSON 数据，UTF-8 编码）
    NSData *postBody = [paramsJSON dataUsingEncoding:NSUTF8StringEncoding];
    [postInfo setPostBody:postBody];
    
    // ===== 5. 构建请求头 =====
    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    // 添加 KG-UA 头（从 SplashBLL 获取）
    SplashBLL *splashBLL = [SplashBLL defaultInstance];
    NSString *webUA = [splashBLL webUA];
    [headers setObjectKGSafe:webUA forKey:@"KG-UA"];
    // 添加 AD-REQUESTID 头（获取广告请求ID）
    NSString *adRequestId = [[self class] getAdRequestId];
    [headers setObjectKGSafe:adRequestId forKey:@"AD-REQUESTID"];
    [postInfo setHeader:headers];
    
    // 填充签名后的 URL（非空时设置）
    if (filledUrl.length > 0) {
        [postInfo setFillUrl:filledUrl];
    }
    
    // ===== 6. 执行 POST 网络请求 =====
    NSDictionary *responseDict = [self doPostWithPostMethodInfo:postInfo AndError:error];
    if (!responseDict) {
        return nil;
    }
    
    // ===== 7. 解析响应结果 =====
    // 读取状态码 & 错误码
    NSNumber *statusNum = [responseDict kg_numberForKey:@"status"];
    NSInteger status = [statusNum asInteger];
    NSNumber *errorCodeNum = [responseDict kg_numberForKey:@"error_code"];
    NSInteger errorCode = [errorCodeNum asInteger];
    
    KGSplashModel *splashModel = nil;
    NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
    NSString *fitAdKey = @"KGSplashADSeverISFitAdForClient";
    
    // 分支1：请求成功（status = 1）
    if (status == 1) {
        // 转换为启动页广告模型
        BOOL isStartSplash = (splashType == 0);
        splashModel = [KGSplashModel convetToKGSplashModel:responseDict isStartSplash:isStartSplash];
        
        // 标记服务器是否适配广告
        BOOL hasRecommendAds = [splashModel hasRecommendAds];
        [userDefaults setObject:hasRecommendAds ? @"1" : @"0" forKey:fitAdKey];
        [userDefaults synchronize];
    
    // 分支2：请求失败（status != 1）
    } else {
        // 解析 data 字段 & 存储公网 IP
        NSDictionary *dataDict = [responseDict kg_dictionaryForKey:@"data"];
        if (dataDict) {
            NSString *publicIP = [dataDict stringForKeyKGSafe:@"ip"];
            if (publicIP) {
                [splashBLL storePublicIP:publicIP];
            }
        }
        
        // 转换为启动页模型（兼容失败场景）
        BOOL isStartSplash = (splashType == 0);
        splashModel = [KGSplashModel convetToKGSplashModel:responseDict isStartSplash:isStartSplash];
        
        // 检查 data 中是否包含 ads 字段
        NSArray *dataKeys = dataDict.allKeys;
        if ([dataKeys containsObject:@"ads"]) {
            // 含 ads 字段 → 标记无适配广告 + 生成特定错误（0x802CA）
            [userDefaults setObject:@"0" forKey:fitAdKey];
            [userDefaults synchronize];
            if (error) {
                *error = [[BaseError alloc] initWithDomain:_kKGErrorDomainTypeTransaction
                                                      code:0x802CA
                                                  userInfo:nil];
            }
        } else {
            // 不含 ads 字段 → 标记无适配广告 + 生成服务器错误码（errorCode + 1000）
            [userDefaults setObject:@"0" forKey:fitAdKey];
            [userDefaults synchronize];
            if (error) {
                *error = [BaseError createErrorWithServerErrorCode:errorCode + 1000 errorMsg:nil];
            }
        }
    }
    
    // ===== 8. 返回结果模型 =====
    return splashModel;
}


// [KGTencentStatistics q36]
// -[KGSplashHttpDao requestRealTimeSplashWithRequestId:downloadAds:isStartSplash:customParam:error:]
// -[KGSplashHttpDao requestSplashList:downloadAds:customParam:Error:]
// -[KGAlertHttpDao queryPopupDialog:popupHistory:scene:withError:]
// -[KGMusicHomeBannerDao requestOperationAdWithOwnAds:error:]
// -[KGSearchNoFocusWordBLL updateNoFocusWordWithIsFromBootUp:withEntrance:needChangeImmediately:finishBlock:]
// -[AdBannerInfoDao getDownloadSheetAdBannerWithError:]
// -[AdHttpDao requestSidebarLinkWithOldAds:error:]
// -[KGHttpRequest asynCompletion:handler:]
// -[KGHttpRequest checkNetwork:]
// 0x107257914 kugou!-[KGHttpRequest asynStartWithCompletionHandler:]
@end