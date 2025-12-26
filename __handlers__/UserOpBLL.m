
@interface UserOpBLL : NSObject
@end

@implementation UserOpBLL 
@end

+ (UserOpBLL *)shareUserInfo {
    static dispatch_once_t onceToken;
    static UserOpBLL *sharedInstance = nil;
    
    dispatch_once(&onceToken, ^{
        // 1. 检查是否已存在共享实例
        if (sharedInstance) return;
        
        // 2. 创建新的UserOpBLL实例
        sharedInstance = [[NSObject alloc] init];
        [sharedInstance initKGAppMoudleWithConfiguration];
        
        // 3. 从配置中读取用户ID
        NSString *userId = [[KGUserInfoSettingConfig shareInstance] readStringValuesForKey:@"userId"];
        
        // 4. 验证用户ID是否有效
        if ( {
            // 5. 从plist文件获取用户信息
            UserOpBLL *userInfo = [UserOpBLL getUserInfoFromPlistFile];
            if (userInfo) {
                // 6. 恢复用户头像
                [sharedInstance recoverUserHeadImageWithUserInfo:userInfo];
                sharedInstance = userInfo;
            } else {
                // 7. 创建默认网络用户信息
                sharedInstance = [[NetUserInfo alloc] init];
                [sharedInstance initKGAppMoudleWithConfiguration];
            }
        } else {
            // 8. 创建默认网络用户信息
            sharedInstance = [[NetUserInfo alloc] init];
            [sharedInstance initKGAppMoudleWithConfiguration];
        }
        
        // 9. 创建副本并设置共享实例
        UserOpBLL *copyInstance = [sharedInstance copy];
        sharedInstance = copyInstance;
        
        // 10. 注册通知观察者
        NSNotificationCenter *center = [NSNotificationCenter defaultCenter];
        
        // 关注完成通知
        [center addObserver:sharedInstance
                    selector:@selector(handleFollowCompleteNoti:)
                        name:@"FOLLOW_COMPLETION_NOTIFICATION"
                        object:nil];
        
        // 取消关注完成通知
        [center addObserver:sharedInstance
                    selector:@selector(handleUnFollowCompleteNoti:)
                        name:@"UNFOLLOW_COMPLETION_NOTIFICATION"
                        object:nil];
        
        // 11. 注册心跳统计观察者
        KGHeartBeatStatistics *heartBeat = [KGHeartBeatStatistics setBaseContext];
        [heartBeat registerObserver:sharedInstance];
    });
    
    return sharedInstance;
}