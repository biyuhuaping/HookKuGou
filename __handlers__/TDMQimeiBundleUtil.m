
// TDMQimeiBundleUtil.m
@interface TDMQimeiBundleUtil : NSObject
+ (NSString *)getQimeiJsonWithAppkey:(NSString *)appkey error:(NSError **)error;
+ (BOOL)saveQimeiJson:(NSString *)qimeiJson withAppkey:(NSString *)appkey error:(NSError **)error;
@end


+ (NSString *)getQimeiJsonWithAppkey:(NSString *)appkey error:(NSError **)error{
    NSString *qimeiJson = nil;

    BOOL isCloneApp = [self isCloneApp];

    // 用 appkey 派生出 keychain 的 username
    NSString *qimeiKey = [self qimeiKeyWithAppkey:appkey];

    // ① 优先从 Keychain（按 appkey）取
    qimeiJson = [self getPasswordForUsername:qimeiKey andServiceName:@"tencent.beacon.analytics" accAttribute:nil error:error];

    // ② 如果 appkey 对应的 keychain 没有
    if (qimeiJson.length == 0) {
        // ②-1 尝试老 key：beacon.qimei
        NSString *legacyQimei = [self getPasswordForUsername:@"beacon.qimei"
                                             andServiceName:@"tencent.beacon.analytics"
                                               accAttribute:nil
                                                      error:nil];

        if (legacyQimei.length > 0) {
            qimeiJson = legacyQimei;
            // 把老 qimei 迁移到 appkey 专属 key
            [self saveQimeiJson:qimeiJson withAppkey:appkey error:nil];
        }
        // 如果 error 指针存在，保持 error 传递
    }

    NSError *queryError = error ? *error : nil;

    // ③ 校验 Qimei & 错误状态（上报 / 统计）
    [self checkQueryQimeiError:appkey queryError:queryError qimeiJson:qimeiJson];

    // ④ 克隆 App 场景：直接清空 Qimei
    if (isCloneApp && qimeiJson.length > 0) {
        // 异步上报 clone qimei
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            sub_10CF37D2C(qimeiJson, appkey);
        });

        // 删除 legacy key
        [self deleteItemForUsername:@"beacon.qimei"
                     andServiceName:@"tencent.beacon.analytics"
                              error:nil];

        // 删除 appkey key
        NSString *appKeyKey = [self qimeiKeyWithAppkey:appkey];
        [self deleteItemForUsername:appKeyKey
                     andServiceName:@"tencent.beacon.analytics"
                              error:nil];

        // clone 清理日志
        sub_10CF39600(1, appkey, @"Qimei Clone clear");
        qimeiJson = nil;
    }

    // 日志：最终是否拿到 qimei
    sub_10CF39600(1, appkey, @"got qimei by keychain %@", qimeiJson);

    // 保证返回非 nil
    NSString *result = qimeiJson ?: @"";
    return result;
}

+ (NSString *)getQimeiJsonWithAppkey:(NSString *)appkey error:(NSError **)error{
    NSString *qimeiJson = nil;
    NSError *queryError = nil;

    // 是否克隆 App
    BOOL isClone = [self isCloneApp];

    // appkey retain
    NSString *key = [appkey retain];

    // ===== 1. 生成 Keychain key =====
    NSString *qimeiKey = [[self qimeiKeyWithAppkey:key] retain];

    // ===== 2. 优先从 appkey 专属 keychain 取 =====
    qimeiJson = [[self getPasswordForUsername:qimeiKey
                              andServiceName:@"tencent.beacon.analytics"
                                accAttribute:nil
                                       error:error] retain];

    [qimeiKey release];

    // ===== 3. 如果没取到，尝试 legacy key =====
    if (qimeiJson.length == 0) {
        NSString *legacyQimei =
            [[self getPasswordForUsername:@"beacon.qimei"
                           andServiceName:@"tencent.beacon.analytics"
                             accAttribute:nil
                                    error:nil] retain];

        if (legacyQimei.length > 0) {
            // 用老 qimei
            [qimeiJson release];
            qimeiJson = [legacyQimei retain];

            // 写回 appkey key
            [self saveQimeiJson:qimeiJson
                     withAppkey:key
                          error:nil];
        }

        [legacyQimei release];

        if (error) {
            queryError = *error;
        }
    } else {
        if (error) {
            queryError = *error;
        }
    }

    // ===== 4. 校验 / 打点 =====
    [self checkQueryQimeiError:key queryError:queryError qimeiJson:qimeiJson];

    // ===== 5. clone App 处理 =====
    if (isClone && qimeiJson.length > 0) {
        // —— 异步上报 clone Qimei
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            [[TDMQimeiApmInterface defaultInterface] postCloneWithQimeiJson:qimeiJson appkey:key];
        });

        // —— 删除 legacy key
        [self deleteItemForUsername:@"beacon.qimei"
                     andServiceName:@"tencent.beacon.analytics"
                              error:nil];

        // —— 删除 appkey key
        NSString *appKeyKey = [[self qimeiKeyWithAppkey:key] retain];
        [self deleteItemForUsername:appKeyKey
                     andServiceName:@"tencent.beacon.analytics"
                              error:nil];
        [appKeyKey release];

        // —— clone 清理日志
        sub_10CF39600(1, key, @"Qimei Clone clear");

        [qimeiJson release];
        qimeiJson = nil;
    }

    // ===== 6. 最终日志 =====
    sub_10CF39600(1, key, @"got qimei by keychain %@", qimeiJson);

    // ===== 7. 保证返回非 nil =====
    NSString *result = qimeiJson ? qimeiJson : @"";
    [result retain];

    [qimeiJson release];
    [key release];

    return [result autorelease];
}

// 校验 Qimei & 错误状态（上报 / 统计）
+ (void)checkQueryQimeiError:(id)appkey queryError:(NSError *)error qimeiJson:(NSString *)qimeiJson{
    if (error) {
        NSString *codeStr = [NSString stringWithFormat:@"%ld", error.code];
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            [[TDMQimeiApmInterface defaultInterface] postKeychainErrorWithAppkey:appkey errorCode:0x3F0 desc:codeStr];
        });
        return;
    }

    if (qimeiJson.length != 0) {
        return;
    }

    NSString *key = [NSString stringWithFormat:@"%@%@", appkey, @"qimei_has_saved"];
    BOOL hasSaved = [[NSUserDefaults standardUserDefaults] boolForKey:key];

    if (hasSaved) {
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            [[TDMQimeiApmInterface defaultInterface] postKeychainErrorWithAppkey:appkey errorCode:0x3F0 desc:nil];
        });
    }
}


// 读取钥匙串，
// +[TDMQimeiBundleUtil getPasswordForUsername:andServiceName:accAttribute:error:]
+ (NSString *)getPasswordForUsername:(NSString *)username
                     andServiceName:(NSString *)service
                       accAttribute:(NSString *__autoreleasing *)accAttribute
                              error:(NSError *__autoreleasing *)error{
    if (!username || !service) {
        if (error) {
            *error = [NSError errorWithDomain:@"QimeiKeychainUtilsErrorDomain" code:-2000 userInfo:nil];
        }
        return nil;
    }

    if (error) *error = nil;

    // ---------- 构造基础 query ----------
    NSDictionary *baseQuery = @{
        (__bridge id)kSecClass        : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount  : username,
        (__bridge id)kSecAttrService  : service
    };

    // ---------- ① 查 attributes ----------
    NSMutableDictionary *attrQuery = [baseQuery mutableCopy];
    attrQuery[(__bridge id)kSecReturnAttributes] = @YES;

    CFTypeRef attrResult = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)attrQuery,&attrResult);

    NSString *outAccAttr = nil;

    if (status == errSecSuccess) {
        NSDictionary *attrDict = (__bridge_transfer NSDictionary *)attrResult;
        id acc = attrDict[(__bridge id)kSecAttrAccessible];

        if ([acc isKindOfClass:[NSString class]] && accAttribute) {
            *accAttribute = acc;
            outAccAttr = acc;
        }
    }

    // ---------- attributes 错误 ----------
    if (status != errSecSuccess && status != errSecItemNotFound) {
        if (error) {
            *error = [NSError errorWithDomain:@"QimeiKeychainUtilsErrorDomain" code:status userInfo:nil];
        }
        return nil;
    }

    // ---------- ② 查 password data ----------
    NSMutableDictionary *dataQuery = [baseQuery mutableCopy];
    dataQuery[(__bridge id)kSecReturnData] = @YES;

    CFTypeRef dataResult = NULL;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)dataQuery, &dataResult);

    if (status == errSecItemNotFound) {
        return nil;
    }

    if (status != errSecSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:@"QimeiKeychainUtilsErrorDomain" code:status userInfo:nil];
        }
        return nil;
    }

    NSData *passwordData = (__bridge_transfer NSData *)dataResult;
    if (!passwordData) {
        if (error) {
            *error = [NSError errorWithDomain:@"QimeiKeychainUtilsErrorDomain" code:-1999 userInfo:nil];
        }
        return nil;
    }

    // ---------- 转 NSString ----------
    NSString *password =
        [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding];

    if (!password && error) {
        *error = [NSError errorWithDomain:@"QimeiKeychainUtilsErrorDomain" code:-1999 userInfo:nil];
    }
    return password;
}
