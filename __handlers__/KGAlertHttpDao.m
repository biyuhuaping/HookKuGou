#import <Foundation/Foundation.h>

// 前置声明依赖类
@class KGAlertResCtrlManager, UserOpBLL, KGTencentStatistics, KGNetworkTools, PostMethodInfo, KGPopupResource, BaseError;

@interface KGAlertHttpDao : NSObject
- (NSDictionary *)queryPopupDialog:(NSArray *)popupDialogs 
                    popupHistory:(NSDictionary *)popupHistory 
                           scene:(NSInteger)scene 
                       withError:(NSError **)error;
@end

@implementation KGAlertHttpDao

- (NSDictionary *)queryPopupDialog:(NSArray *)popupDialogs 
                    popupHistory:(NSDictionary *)popupHistory 
                           scene:(NSInteger)scene 
                       withError:(NSError **)error {
    // ===== 1. 弹窗请求前置统计埋点 =====
    // 遍历弹窗列表，记录请求统计（是否热启动）
    if (popupDialogs.count > 0) {
        for (id popupItem in popupDialogs) {
            @autoreleasepool {
                KGAlertResCtrlManager *resCtrl = [KGAlertResCtrlManager sharedInstance];
                NSString *popupId = [popupItem popupId];
                NSNumber *isHotLaunch = [popupItem te_isHotLaunch];
                // 埋点：弹窗请求统计
                [resCtrl popupRequestStatistic:popupId isHotLaunch:isHotLaunch];
            }
        }
    }
    
    // ===== 2. 构建基础请求参数 =====
    // 获取用户信息
    UserOpBLL *userOp = [UserOpBLL shareUserInfo];
    NSMutableDictionary *requestParams = [NSMutableDictionary dictionary];
    
    // 2.1 添加客户端时间戳（秒级）
    NSTimeInterval timestamp = [[NSDate date] timeIntervalSince1970];
    NSNumber *timeNum = [NSNumber numberWithDouble:timestamp];
    [requestParams setObjectKGSafe:timeNum.stringValue forKey:@"clienttime"];
    
    // 2.2 添加腾讯统计 q36 参数
    KGTencentStatistics *stat = [KGTencentStatistics sharedInstance];
    NSString *q36Value = [stat q36];
    [requestParams setObjectKGSafe:q36Value forKey:@"q36"];
    
    // 2.3 合并弹窗历史/场景参数
    NSDictionary *postBodyDict = [self postBodyDict:popupDialogs popupHistory:popupHistory scene:scene];
    [requestParams addEntriesFromDictionary:postBodyDict];
    
    // ===== 3. 生成请求签名 & 构建 POST 请求 =====
    // 转换参数为 JSON 字符串
    NSString *paramsJSON = [requestParams JSONString2];
    // 签名并填充 URL（非CDN请求，无自定义签名）
    KGNetworkTools *networkTools = [KGNetworkTools sharedInstance];
    NSString *filledUrl = [networkTools signFillUrlCustomParameterDictionary:requestParams.copy
                                                               bodyString:paramsJSON
                                                            isCdnRequest:NO
                                                               signature:nil];
    
    // 构建 POST 请求配置
    PostMethodInfo *postInfo = [[PostMethodInfo alloc] init];
    // 设置请求 URL 密钥（弹窗资源控制 v2 接口）
    [postInfo setUrlKey:@"listen.popup.url.resource_control_v2"];
    // 设置请求体（JSON 数据，UTF-8 编码）
    NSData *postBody = [paramsJSON dataUsingEncoding:NSUTF8StringEncoding];
    [postInfo setPostBody:postBody];
    // 设置返回数据类型为 JSON（0 = JSON）
    [postInfo setReturnDataType:0];
    // 非仅 WiFi 环境请求
    [postInfo setAskWithOnlyWifi:NO];
    
    // ===== 4. 构建请求头 =====
    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    // 添加 UserAgent（标记为弹窗查询）
    [headers setObject:@"PopupDialogQuery" forKey:@"UserAgent"];
    // 添加用户ID/Token（从用户信息中获取）
    NSNumber *userId = [userOp userID];
    NSString *token = [userOp token];
    [headers setObjectKGSafe:userId forKey:@"userid"];
    [headers setObjectKGSafe:token forKey:@"token"];
    [postInfo setHeader:headers];
    
    // 填充签名后的 URL
    if (filledUrl) {
        [postInfo setFillUrl:filledUrl];
    }
    
    // ===== 5. 执行 POST 网络请求 =====
    NSDictionary *responseDict = [self doPostWithPostMethodInfo:postInfo AndError:error];
    if (!responseDict) {
        return nil;
    }
    
    // ===== 6. 解析响应结果 =====
    // 读取状态码（1 = 成功）
    NSInteger status = [responseDict integerForKeyKGSafe:@"status"];
    if (status == 1) {
        // 分支1：请求成功 → 解析弹窗列表
        NSDictionary *dataDict = [responseDict dictionaryForKeyKGSafe:@"data"];
        NSArray *popupList = [dataDict arrayForKeyKGSafe:@"popup_list"];
        
        NSMutableDictionary *popupModels = [NSMutableDictionary dictionaryWithCapacity:popupList.count];
        for (NSInteger i = 0; i < popupList.count; i++) {
            @autoreleasepool {
                // 解析单个弹窗字典 → 转换为 KGPopupResource 模型
                NSDictionary *popupDict = [popupList dictionaryAtIndexKGSafe:i];
                KGPopupResource *popupModel = [KGPopupResource yy_modelWithDictionary:popupDict];
                // 设置模型索引
                [popupModel setIndex:i];
                // 存入字典（key = popupId）
                [popupModels setObjectKGSafe:popupModel forKey:popupModel.popupId];
                
                // 埋点：弹窗响应成功统计（respStatus = 1）
                KGAlertResCtrlManager *resCtrl = [KGAlertResCtrlManager sharedInstance];
                [resCtrl popupResponseStatistic:popupModel.popupId respStatus:1];
            }
        }
        return popupModels.copy;
        
    } else {
        // 分支2：请求失败 → 生成错误对象 + 埋点失败统计
        NSInteger errorCode = [responseDict integerForKeyKGSafe:@"error_code"];
        if (error) {
            *error = [BaseError createErrorWithServerErrorCode:errorCode errorMsg:nil];
        }
        
        // 遍历原始弹窗列表，埋点响应失败统计（respStatus = 2）
        if (popupDialogs.count > 0) {
            for (id popupItem in popupDialogs) {
                @autoreleasepool {
                    KGAlertResCtrlManager *resCtrl = [KGAlertResCtrlManager sharedInstance];
                    NSString *popupId = [popupItem popupId];
                    [resCtrl popupResponseStatistic:popupId respStatus:2];
                }
            }
        }
        return nil;
    }
}

@end