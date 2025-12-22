- (NSString *)uid {
    return _uid;  // 直接返回实例变量
}

- (void)setUid:(NSString *)uid {
    objc_storeStrong(&_uid, uid);  // 使用ARC语义设置实例变量
}