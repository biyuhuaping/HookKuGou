@interface ZBHTextWindowCount : NSObject    
@property (nonatomic, strong, readonly) ZBHObjectFloatContent *jumpAllModeImpl;
@end

@implementation ZBHTextWindowCount

- (void)launchRDelivery {
    RDeliveryDepends *depends = [RDeliveryDepends new];
    depends.httpImpl = [RDNetworkImpl sharedInstance];//设置网络实现
    depends.logImpl  = [RDLoggerImpl sharedInstance];//设置日志实现
    depends.kvImpl   = [RDMMKVFactoryImpl sharedInstance];//设置键值存储实现
    depends.jsonModelImpl = [RDeliveryJsonModelImpl sharedInstance];//设置JSON模型实现

    // 3. 从 jumpAllModeImpl 拿各种运行参数
    ZBHTextWindowCount *jump = [self jumpAllModeImpl];
    NSString *appId     = [jump makeDoubleFromProcessor];
    NSString *appKey    = [jump appKey];//b1ec752-1349-49af-aacb-f9d25197bce9（__NSCFString）
    NSString *guid      = [jump uid];//:11ca09173e0e2c6121e2f5a55354fa88888（__NSCFString）
    NSString *appVer    = [jump appVersion];//20449（NSTaggedPointerString）
    NSString *qimei     = [jump deviceID];//:de200408f3f04354795413b01dd77c57d0967c52（__NSCFString）
    NSString *sysVer    = [jump systemVersion];//15.2（NSTaggedPointerString）

    // appId = @"10021"
    RDeliverySDKSettings *settings = [RDeliverySDKSettings settingWithAppId:appId
                             systemId:@"10021"
                                appKey:appKey
                                  guid:uid
                               depends:depends];
                               
    // 4. 填充 settings
    settings.appVersion    = appVersion;
    settings.qimei         = qimei;
    settings.updateMode    = 15;
    settings.updateDuration = 14400.0;
    settings.systemVersion = sysVer;
    settings.platform      = 3;//平台 iOS
    settings.pullTarget    = 1;//拉取目标

   // 5. 环境判断
    NSString *envId = kRDeliveryEnvTest;
    if ([jump setRealRightButton]) {
        envId = kRDeliveryEnvProd;
    }
    settings.envId = envId;

    // 10. 创建 SDK
    RDeliverySDK *sdk = [RDeliverySDK createSDKWithSettings:settings];
    self.rdelivery = sdk;
}


- (ZBHTextWindowCount *)jumpAllModeImpl {
    return [self _jumpAllModeImpl];  // 直接返回实例变量
}

// 等效的ARC代码：
- (void)setJumpAllModeImpl:(ZBHTextWindowCount *)jumpAllModeImpl {
    if (_jumpAllModeImpl != jumpAllModeImpl) {
        _jumpAllModeImpl = jumpAllModeImpl;
    }
}


- (void)updateUid:(NSString *)uid {
    // 1. 检查条件，如果满足条件则直接返回
    if (sub_10CDB2A9C() & 1) {
        [uid release];
        return;
    }
    
    // 2. 获取队列并异步执行
    dispatch_queue_t queue = [self queue];
    dispatch_async(queue, ^{
        @autoreleasepool {
            // 3. 记录日志
            const char *uidCStr = [uid UTF8String];
            NSLog(@"[R CONFIG] update uid %s", uidCStr);
            
            // 4. 检查是否需要更新
            ZBHObjectFloatContent *config = [self jumpAllModeImpl];
            NSString *currentUid = [config uid];
            
            if ( {
                // 5. 更新配置中的用户ID
                [config setUid:uid];
                
                // 6. 通知RDelivery SDK切换用户
                RDeliverySDK *rdelivery = [self rdelivery];
                [rdelivery switchGuid:uid];
                
                // 7. 请求新的配置并下载
                [self reqeustSettingsAndDownload];
            }
        }
    });
}


@end