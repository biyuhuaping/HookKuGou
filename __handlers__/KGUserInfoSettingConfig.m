@implementation KGUserInfoSettingConfig

- (id)readStringValuesForKey:(id)key{
    __block id result = nil;

    // 获取串行队列
    dispatch_queue_t queue = [self ioQueue];

    // 同步执行 block
    dispatch_sync(queue, ^{
        // 内部逻辑见 sub_1091A32FC
        NSDictionary *dict = self.userInfoDict;
        id value = [dict stringForKeyKGSafe:key];
        result = value;
    });

    return result;
}

@end