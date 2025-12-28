// frida-trace -D fa6f4e5a190858ab2441952057f189eb5c15b595 -f com.kugou.kugou1002 -m "+[NSJSONSerialization dataWithJSONObject:options:error:]"

#import <Foundation/Foundation.h>

@interface RDHttpSession : NSObject
@property (nonatomic, strong) id settings;
@property (nonatomic, strong) id mediatorCenter;
@end

@interface RDHttpRequest : NSObject
@property (nonatomic, copy) NSString *requestUrl;
@property (nonatomic, copy) NSString *requestMethod;
@property (nonatomic, assign) double timeout;
@property (nonatomic, assign) NSInteger requestCachePolicy;
@property (nonatomic, copy) NSDictionary *headerFields;
@property (nonatomic, copy) NSDictionary *parameters;
@property (nonatomic, strong) NSData *httpBody;
@property (nonatomic, copy) NSString *sign;
@property (nonatomic, copy) NSDictionary *reportParams;
@property (nonatomic, assign) NSTimeInterval batchRequestStartTime;
@end

@interface RDeliverySDKSettings : NSObject
@property (nonatomic, assign) double timeout;
@property (nonatomic, strong) id mediatorCenter;
@property (nonatomic, copy) NSString *appId;
@property (nonatomic, copy) NSString *systemId;
@end

@interface RDMediatorCenter : NSObject
@property (nonatomic, strong) id jsonModelMediator;
@property (nonatomic, strong) id logMediator;
@end

@interface RDeliveryJsonModelMediator : NSObject
- (NSData *)modelToJSONData:(id)model;
@end

@interface RDLogMediator : NSObject
- (void)log:(NSInteger)level 
        tag:(NSString *)tag 
    fileName:(const char *)fileName 
  lineNumber:(NSInteger)lineNumber 
    function:(const char *)function 
     content:(NSString *)content, ...;
@end

@implementation RDHttpSession

- (RDHttpRequest *)pullConfigRequestWithTask:(id)task {
    @autoreleasepool {
        RDHttpRequest *request = [[RDHttpRequest alloc] init];
        
        // 1. 设置请求基本信息
        request.batchRequestStartTime = [task batchRequestStartTime];
        request.requestUrl = [self pullConfigRequestUrl];
        request.requestMethod = @"POST";
        
        // 2. 设置超时时间
        RDeliverySDKSettings *settings = [self settings];
        double timeout = [settings timeout];
        
        if ([task hasNext]) {
            NSTimeInterval currentTime = [[NSDate date] timeIntervalSince1970];
            NSTimeInterval firstRequestTime = [task firstRequestSendTime];
            timeout = MAX(timeout - (currentTime - firstRequestTime), 3.0);
        }
        request.timeout = timeout;
        
        // 3. 设置请求策略和头部
        request.requestCachePolicy = 1; // NSURLRequestReloadIgnoringLocalCacheData
        request.parameters = nil;
        request.headerFields = @{
            @"Content-Type": @"application/json"
        };
        
        // 4. 准备请求体
        id requestBody = [self requestBodyWithTask:task];
        
        RDeliverySDKSettings *currentSettings = [self settings];
        RDMediatorCenter *mediatorCenter = [currentSettings mediatorCenter];
        RDeliveryJsonModelMediator *jsonMediator = [mediatorCenter jsonModelMediator];
        NSData *jsonData = [jsonMediator modelToJSONData:requestBody];
        
        if (jsonData) {
            // 5. 处理请求体
            NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            [task setHttpBody:jsonString];
            
            // 6. 记录日志
            RDMediatorCenter *logMediatorCenter = [currentSettings mediatorCenter];
            RDLogMediator *logMediator = [logMediatorCenter logMediator];
            [logMediator log:3
                         tag:@"[RDelivery][RDHttpSession]"
                    fileName:"RDHttpSession.m"
                  lineNumber:395
                    function:"pullConfigRequestWithTask:"
                     content:@"拉取配置请求URL:%@ Body：\n%@", 
                      request.requestUrl, jsonString];
            
            // 7. 设置签名
            NSString *sign = [requestBody sign];
            request.sign = sign;
            
            // 8. 加密数据
            NSData *encryptedData = [self encryptPullConfigTask:task data:jsonData];
            request.httpBody = encryptedData;
            
            // 9. 设置上报参数
            NSString *appId = [currentSettings appId] ?: @"";
            NSString *systemId = [currentSettings systemId] ?: @"";
            
            request.reportParams = @{
                @"app_id": appId,
                @"sys_id": systemId
            };
            
            return request;
        } else {
            // JSON序列化失败
            RDeliverySDKSettings *failSettings = [self settings];
            RDMediatorCenter *failMediatorCenter = [failSettings mediatorCenter];
            RDLogMediator *failLogMediator = [failMediatorCenter logMediator];
            [failLogMediator log:4
                             tag:@"[RDelivery][RDHttpSession]"
                        fileName:"RDHttpSession.m"
                      lineNumber:389
                        function:"pullConfigRequestWithTask:"
                         content:@"拉取配置json组包失败！%@", task];
            
            return nil;
        }
    }
}

- (NSString *)uuid {
    // 使用同步队列保证线程安全
    static dispatch_once_t onceToken;
    static dispatch_semaphore_t lock = NULL;
    static dispatch_once_t oncePredicate;
    dispatch_once(&oncePredicate, ^{
        lock = dispatch_semaphore_create(1);
    });
    
    dispatch_semaphore_wait(lock, DISPATCH_TIME_FOREVER);
    
    @autoreleasepool {
        if (!_uuid) {
            NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
            NSString *storedUUID = [userDefaults stringForKey:@"kRDeliveryUUIDStorageKey"];
            
            if (storedUUID && storedUUID.length > 0) {
                _uuid = [storedUUID copy];
            } else {
                // 生成新的UUID
                NSUUID *newUUID = [NSUUID UUID];
                NSString *uuidString = [[newUUID UUIDString] uppercaseString];
                _uuid = [uuidString copy];
                
                // 存储到UserDefaults
                [userDefaults setObject:_uuid forKey:@"kRDeliveryUUIDStorageKey"];
                [userDefaults synchronize];
            }
        }
    }
    
    dispatch_semaphore_signal(lock);
    
    return _uuid;
}

#pragma mark - 辅助方法

- (NSString *)pullConfigRequestUrl {
    // 实现获取配置请求URL
    return @"";
}

- (id)requestBodyWithTask:(id)task {
    // 实现构建请求体
    return nil;
}

- (NSData *)encryptPullConfigTask:(id)task data:(NSData *)jsonData {
    // 实现数据加密
    return jsonData;
}

@end