// Tweak_runtime.m
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <strings.h>
#import "fishhook.h"

// ---------- 配置读取 ----------
// static NSDictionary *configDict(void) {
//     NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/.deviceFakeConfig.plist"];
//     NSURL *url = [NSURL fileURLWithPath:path];
//     NSDictionary *dic = [NSDictionary dictionaryWithContentsOfURL:url];
//     if (!dic) {
//         NSLog(@"[HOOK] Failed to load plist at %@", path);
//         dic = @{};
//     }
//     NSLog(@"[configDict] path at %@", path);
//     return dic[@"config"];
// }

static NSDictionary *cachedConfig = nil;
static NSDictionary *configDict(void) {
    if (cachedConfig) return cachedConfig;
    
    // 尝试多个路径，按优先级顺序
    NSArray *possiblePaths = @[
        @"/var/jb/tmp/deviceFakeConfig.plist",  // 越狱设备（rootless）
        @"/var/tmp/deviceFakeConfig.plist",     // 越狱设备（传统）
        [NSHomeDirectory() stringByAppendingPathComponent:@"Library/deviceFakeConfig.plist"],  // 应用沙盒（未越狱）
        [NSHomeDirectory() stringByAppendingPathComponent:@"Library/.deviceFakeConfig.plist"],  // 应用沙盒（未越狱）
        [NSHomeDirectory() stringByAppendingPathComponent:@"tmp/deviceFakeConfig.plist"],    // 应用沙盒 tmp（未越狱）
    ];
    
    NSString *loadedPath = nil;
    for (NSString *path in possiblePaths) {
        NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
        if (dict) {
            cachedConfig = dict[@"config"];
            loadedPath = path;
            break;
        }
    }
    
    if (!cachedConfig) {
        NSLog(@"[HOOK]config: Failed from all paths: %@", possiblePaths);
        cachedConfig = @{};
    } else {
        NSLog(@"[HOOK]config: Loaded from: %@", loadedPath);
    }
    return cachedConfig;
}
// 强制重新加载配置
// static void reloadConfig(void) {
//     cachedConfig = nil;
//     (void)configDict();
// }

// ---------- 工具：获取顶层控制器（兼容 Scene） ----------
// static UIWindow *currentWindow(void) {
//     UIWindow *keyWindow = nil;

//     if (@available(iOS 13.0, *)) {
//         for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
//             if (scene.activationState == UISceneActivationStateForegroundActive &&
//                 [scene isKindOfClass:[UIWindowScene class]]) {

//                 UIWindowScene *windowScene = (UIWindowScene *)scene;
//                 for (UIWindow *window in windowScene.windows) {
//                     if (window.windowLevel == UIWindowLevelNormal &&
//                         !window.hidden &&
//                         window.bounds.size.width > 0 &&
//                         window.bounds.size.height > 0) {
//                         keyWindow = window;
//                         break;
//                     }
//                 }
//                 if (keyWindow) break;
//             }
//         }
//     }

//     if (!keyWindow) {
//         for (UIWindow *window in [UIApplication sharedApplication].windows) {
//             if (window.windowLevel == UIWindowLevelNormal &&
//                 !window.hidden &&
//                 window.bounds.size.width > 0 &&
//                 window.bounds.size.height > 0) {
//                 keyWindow = window;
//                 break;
//             }
//         }
//     }

//     if (!keyWindow) {
// #pragma clang diagnostic push
// #pragma clang diagnostic ignored "-Wdeprecated-declarations"
//         keyWindow = [UIApplication sharedApplication].keyWindow;
// #pragma clang diagnostic pop
//     }

//     return keyWindow;
// }


// ---------- 辅助函数 ----------
// static id safe_objc_msgSend_id(id target, SEL sel) {
//     if (!target) return nil;
//     IMP imp = class_getMethodImplementation(object_getClass(target), sel);
//     if (!imp) return nil;
//     id (*fn)(id, SEL) = (void *)imp;
//     return fn(target, sel);
// }

// ---------- UIDevice  ----------
// name
static NSString *(*orig_UIDevice_name)(id, SEL) = NULL;
static NSString *hook_UIDevice_name(id self, SEL _cmd) {
    NSString *origValue = nil;
    if (orig_UIDevice_name) {
        origValue = orig_UIDevice_name(self, _cmd);
    }

    NSDictionary *config = configDict();
    NSString *name = config[@"dName"];

    if (name.length) {
        NSLog(@"[HOOK] UIDevice.name original: %@ -> %@", origValue, name);
        return name;
    } else {
        NSLog(@"[HOOK] UIDevice.name original : %@", origValue);
    }
    return origValue;
}

// identifierForVendor
static NSUUID *(*orig_UIDevice_identifierForVendor)(id, SEL) = NULL;
static NSUUID *hook_UIDevice_identifierForVendor(id self, SEL _cmd) {
    NSUUID *orig = orig_UIDevice_identifierForVendor(self, _cmd);
    NSDictionary *config = configDict();
    NSString *customIDFV = config[@"idfv"];
    if (customIDFV.length) {
        NSUUID *u = [[NSUUID alloc] initWithUUIDString:customIDFV];
        NSLog(@"[HOOK] idfv %@ -> %@",orig.UUIDString, u.UUIDString);
        return u;
    }
    NSLog(@"[HOOK] idfv 原值没改: %@", orig.UUIDString);
    return orig;
}

// systemVersion
static NSString *(*orig_UIDevice_systemVersion)(id, SEL) = NULL;
static NSString *hook_UIDevice_systemVersion(id self, SEL _cmd) {
    NSString *origValue = nil;
    if (orig_UIDevice_systemVersion) {
        origValue = orig_UIDevice_systemVersion(self, _cmd);
    }

    NSDictionary *config = configDict();
    NSString *sVersion = config[@"osv"];

    if (sVersion.length) {
        NSLog(@"[HOOK] UIDevice.systemVersion original: %@ -> %@", origValue, sVersion);
        return sVersion;
    } else {
        NSLog(@"[HOOK] UIDevice.systemVersion original : %@", origValue);
    }
    return origValue;
}



// ---------- ASIdentifierManager advertisingIdentifier ----------
static NSUUID *(*orig_ASID_advertisingIdentifier)(id, SEL) = NULL;
static NSUUID *hook_ASID_advertisingIdentifier(id self, SEL _cmd) {
    NSUUID *orig = orig_ASID_advertisingIdentifier(self, _cmd);
    NSDictionary *config = configDict();
    NSString *customIDFA = config[@"idfa"];
    if (customIDFA.length) {
        NSUUID *u = [[NSUUID alloc] initWithUUIDString:customIDFA];
        NSLog(@"[HOOK] idfa override: %@", u);
        return u;
    }
    NSLog(@"[HOOK] idfa original: %@", orig);
    return orig;
}

// ---------- UIScreen bounds / scale / nativeBounds ----------
static CGRect (*orig_UIScreen_bounds)(id, SEL) = NULL;
static CGRect hook_UIScreen_bounds(id self, SEL _cmd) {
    CGRect value = orig_UIScreen_bounds(self, _cmd);
    // NSLog(@"[Hook] UIScreen.bounds = %.0f x %.0f", value.size.width, value.size.height);

    NSDictionary *config = configDict();
    NSNumber *dx = config[@"dx"];
    NSNumber *dy = config[@"dy"];
    if (dx && dy) {
        return CGRectMake(0, 0, dx.floatValue, dy.floatValue);
        // NSLog(@"[Hook] UIScreen.bounds修改为: %.0f x %.0f", dx.floatValue, dy.floatValue);
    }
    return value;
}

static CGFloat (*orig_UIScreen_scale)(id, SEL) = NULL;
static CGFloat hook_UIScreen_scale(id self, SEL _cmd) {
    CGFloat value = orig_UIScreen_scale(self, _cmd);
    NSDictionary *config = configDict();
    NSNumber *scale = config[@"scale"];
    if (scale) {
        // NSLog(@"[Hook] override scale: %f", scale.floatValue);
        return scale.floatValue;
    }
    return value;
}

static CGRect (*orig_UIScreen_nativeBounds)(id, SEL) = NULL;
static CGRect hook_UIScreen_nativeBounds(id self, SEL _cmd) {
    CGRect value = orig_UIScreen_nativeBounds(self, _cmd);
    // NSLog(@"[Hook] UIScreen.nativeBounds = %.0f x %.0f", value.size.width, value.size.height);
    NSDictionary *config = configDict();
    NSNumber *ndx = config[@"ndx"];
    NSNumber *ndy = config[@"ndy"];
    if (ndx && ndy) {
        CGFloat w = ndx.floatValue;
        CGFloat h = ndy.floatValue;
        // NSLog(@"[Hook] UIScreen.nativeBounds 修改为: %.0f x %.0f", w, h);
        return CGRectMake(0, 0, w, h);
    }
    return value;
}

// ---------- StatisticInfo ----------
static id (*orig_StatisticInfo_sysVer)(id, SEL) = NULL;
static id hook_StatisticInfo_sysVer(id self, SEL _cmd) {
    // 获取原始返回值
    id origValue = nil;
    if (orig_StatisticInfo_sysVer) {
        origValue = orig_StatisticInfo_sysVer(self, _cmd);
    }
    NSDictionary *cfg = configDict();
    NSString *override = cfg[@"osv"]; //@"16.7.11"

    if (override && override.length) {
        NSLog(@"[HOOK] +[StatisticInfo sysVer] original: %@, override: %@", origValue, override);
        return override; // ARC 会以 autoreleased 语义返回
    } else {
        NSLog(@"[HOOK] +[StatisticInfo sysVer] original: %@, no override", origValue);
        return origValue;
    }
}

// ---------- StatisticInfo udid ----------
static id (*orig_StatisticInfo_udid)(id, SEL) = NULL;
static id hook_StatisticInfo_udid(id self, SEL _cmd) {
    // 获取原始返回值
    id origValue = nil;
    if (orig_StatisticInfo_udid) {
        origValue = orig_StatisticInfo_udid(self, _cmd);
    }
    
    // NSDictionary *cfg = configDict();
    NSString *override = @"de200408f3f04354795413b01dd77c57d0967c52";//cfg[@"udid"];//
    if (override.length > 0) {
        NSLog(@"[HOOK] +[StatisticInfo udid] original: %@ -> %@", origValue, override);
        return override;
    } else {
        NSLog(@"[HOOK] +[StatisticInfo udid] original:未修改：%@", origValue);
        return origValue;
    }
}

// ---------- NeeFileCache objectForKey: ----------
// 注意：objectForKeyedSubscript: 是 thunk，实际调用 objectForKey:
// 所以应该 hook objectForKey: 而不是 objectForKeyedSubscript:
static id (*orig_NeeFileCache_objectForKey_)(id, SEL, id) = NULL;
static id hook_NeeFileCache_objectForKey_(id self, SEL _cmd, id key) {
    @autoreleasepool {
        // 立即打印调用信息
        NSString *keyStr = [key respondsToSelector:@selector(description)] ? [key description] : @"<nil>";
        NSLog(@"[HOOK] 🔥 -[NeeFileCache objectForKey:] 被调用! key: %@", keyStr);
        
        // 获取原始返回值
        id origValue = nil;
        if (orig_NeeFileCache_objectForKey_) {
            origValue = orig_NeeFileCache_objectForKey_(self, _cmd, key);
        } else {
            NSLog(@"[HOOK] ⚠️ -[NeeFileCache objectForKey:] 原始实现为空!");
        }
        
        // 判断 key 是否为 @"appUdid"
        if ([key isKindOfClass:[NSString class]] && [key isEqualToString:@"appUdid"]) {
            // 从配置读取是否需要替换
            NSDictionary *cfg = configDict();
            NSString *udidValue = cfg[@"udid"];
            if (udidValue && udidValue.length > 0) {
                NSLog(@"[HOOK] ✅ -[NeeFileCache objectForKey:@\"appUdid\"] 原值: %@ -> %@", origValue, udidValue);
                return udidValue;
            }
            NSLog(@"[HOOK] -[NeeFileCache objectForKey:@\"appUdid\"] 原值: %@ (未修改)", origValue);
        } else {
            NSLog(@"[HOOK] -[NeeFileCache objectForKey:] key: %@, value: %@", keyStr, origValue);
        }
        
        return origValue;
    }
}

// ---------- NeeFileCache objectForKeyedSubscript: (保留用于兼容) ----------
static id (*orig_NeeFileCache_objectForKeyedSubscript_)(id, SEL, id) = NULL;
static id hook_NeeFileCache_objectForKeyedSubscript_(id self, SEL _cmd, id key) {
    @autoreleasepool {
        // 立即打印调用信息
        NSString *keyStr = [key respondsToSelector:@selector(description)] ? [key description] : @"<nil>";
        NSLog(@"[HOOK] 🔥 -[NeeFileCache objectForKeyedSubscript:] 被调用! key: %@", keyStr);
        
        // 获取原始返回值（会调用 objectForKey:）
        id origValue = nil;
        if (orig_NeeFileCache_objectForKeyedSubscript_) {
            origValue = orig_NeeFileCache_objectForKeyedSubscript_(self, _cmd, key);
        } else {
            NSLog(@"[HOOK] ⚠️ -[NeeFileCache objectForKeyedSubscript:] 原始实现为空!");
        }
        
        // 判断 key 是否为 @"appUdid"
        if ([key isKindOfClass:[NSString class]] && [key isEqualToString:@"appUdid"]) {
            // 从配置读取是否需要替换
            // NSDictionary *cfg = configDict();
            NSString *udidValue = @"de200408f3f04354795413b01dd77c57d0967c52";//cfg[@"udid"];//
            if (udidValue.length > 0) {
                NSLog(@"[HOOK] ✅ -[NeeFileCache objectForKeyedSubscript:@\"appUdid\"] 原值: %@ -> %@", origValue, udidValue);
                return udidValue;
            }
            NSLog(@"[HOOK] -[NeeFileCache objectForKeyedSubscript:@\"appUdid\"] 原值: %@ (未修改)", origValue);
        } else {
            NSLog(@"[HOOK] -[NeeFileCache objectForKeyedSubscript:] key: %@, value: %@", keyStr, origValue);
        }
        
        return origValue;
    }
}

// ---------- KGTencentStatistics q36 ----------
static NSString *(*orig_KGTencentStatistics_q36)(id, SEL) = NULL;
static NSString *hook_KGTencentStatistics_q36(id self, SEL _cmd) {
    @autoreleasepool {
        // 获取原始返回值
        NSString *origValue = nil;
        if (orig_KGTencentStatistics_q36) {
            origValue = orig_KGTencentStatistics_q36(self, _cmd);
        }
        
        // 从配置读取需要替换的值
        NSDictionary *cfg = configDict();
        NSString *q36Value = cfg[@"q36"];
        
        // 如果配置中有值，使用配置的值；否则使用原始值
        if (q36Value && [q36Value isKindOfClass:[NSString class]] && q36Value.length > 0) {
            NSLog(@"[HOOK] -[KGTencentStatistics q36]:%@ -> %@", origValue, q36Value);
            return q36Value;
        } else {
            NSLog(@"[HOOK] -[KGTencentStatistics q36]:%@ -> 未修改", origValue);
            return origValue;
        }
    }
}

// ---------- TDeviceInfoUtil GetQIMEI: ----------
static id (*orig_TDeviceInfoUtil_GetQIMEI_)(id, SEL, id) = NULL;
static id hook_TDeviceInfoUtil_GetQIMEI_(id self, SEL _cmd, id arg1) {
    @autoreleasepool {
        // 获取原始返回值
        id origValue = nil;
        if (orig_TDeviceInfoUtil_GetQIMEI_) {
            origValue = orig_TDeviceInfoUtil_GetQIMEI_(self, _cmd, arg1);
        }
        // 从配置读取是否需要替换
        NSDictionary *cfg = configDict();
        NSString *qimeiValue = cfg[@"q36"];//8P 16.1.1：fae0c6104adffedfd37614e500001de19917
        
        // 如果配置中有值，使用配置的值；否则使用原始值
        if (qimeiValue && [qimeiValue isKindOfClass:[NSString class]] && qimeiValue.length > 0) {
            NSLog(@"[HOOK] GetQIMEI: 返回值 %@ -> %@", origValue, qimeiValue);
            return qimeiValue;
        } else {
            NSLog(@"[HOOK] GetQIMEI: 返回原始值 : %@", origValue);
            return origValue;
        }
    }
}

// ---------- ZBHObjectFloatContent uid ----------
static id (*orig_ZBHObjectFloatContent_uid)(id, SEL) = NULL;
static id hook_ZBHObjectFloatContent_uid(id self, SEL _cmd) {
    @autoreleasepool {
        // 获取原始返回值
        id origValue = nil;
        if (orig_ZBHObjectFloatContent_uid) {
            origValue = orig_ZBHObjectFloatContent_uid(self, _cmd);
        }
        
        // 从配置读取是否需要替换
        NSDictionary *cfg = configDict();
        NSString *uidValue = cfg[@"q36"];
        // 如果配置中有值，使用配置的值；否则使用原始值
        if (uidValue && [uidValue isKindOfClass:[NSString class]] && uidValue.length > 0) {
            NSLog(@"[HOOK] -[ZBHObjectFloatContent uid]: %@ -> %@", origValue, uidValue);
            return uidValue;
        } else {
            NSLog(@"[HOOK] -[ZBHObjectFloatContent uid]: 返回原始值");
            return origValue;
        }
    }
}


// ---------- NSURLRequest allHTTPHeaderFields ----------
static NSDictionary *(*orig_NSURLRequest_allHTTPHeaderFields)(id, SEL) = NULL;
static NSDictionary *hook_NSURLRequest_allHTTPHeaderFields(id self, SEL _cmd) {
    NSDictionary *orig = orig_NSURLRequest_allHTTPHeaderFields(self, _cmd);
    NSMutableDictionary *headers = orig ? [orig mutableCopy] : [NSMutableDictionary dictionary];
    NSLog(@"[Hook] User-Agent original: %@", headers);
    return headers;
}

// ---------- NSURLSession dataTaskWithRequest:completionHandler: ----------
// static NSURLSessionDataTask *(*orig_NSURLSession_dataTaskWithRequest_completionHandler)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)) = NULL;
// static NSURLSessionDataTask *hook_NSURLSession_dataTaskWithRequest_completionHandler(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *)) {
//     NSString *url = request.URL.absoluteString;
//     NSLog(@"[hook] RequestURL: %@", url);
//     __block NSString *requestBody = nil;
//     if (request.HTTPBody) {
//         requestBody = [[NSString alloc] initWithData:request.HTTPBody encoding:NSUTF8StringEncoding];
//         NSLog(@"[hook] Request Body: %@", requestBody);
//     }
//     void (^customCompletion)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
//         NSString *responseBody = @"<nil>";
//         if (data) {
//             NSString *tmp = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
//             if (tmp) responseBody = tmp;
//         }
//         NSLog(@"[hook] 请求：%@\n入参：%@\n出参：%@", url, requestBody, responseBody);
//         if (completionHandler) completionHandler(data, response, error);
//     };
//     return orig_NSURLSession_dataTaskWithRequest_completionHandler(self, _cmd, request, customCompletion);
// }



// ---------- sysctlbyname via fishhook ----------
static int (*orig_sysctlbyname)(const char *, void *, size_t *, const void *, size_t) = NULL;
// MARK: - 工具函数：安全读取原始 sysctl 值
static NSString *getOrigSysctlString(const char *name) {
    size_t size = 0;
    if (orig_sysctlbyname(name, NULL, &size, NULL, 0) != 0 || size == 0) return nil;

    char *buf = (char *)malloc(size);
    if (!buf) return nil;

    if (orig_sysctlbyname(name, buf, &size, NULL, 0) != 0) {
        free(buf);
        return nil;
    }

    NSString *val = [NSString stringWithUTF8String:buf ?: ""];
    free(buf);
    NSLog(@"[hook] sysctlbyname: %s 原值: %@", name, val);
    return val;
}
// MARK: - 工具函数：安全写入 hook 值
static int setSysctlOverride(const char *name, NSString *orig, NSString *override, void *oldp, size_t *oldlenp) {
    if (!override || !override.length) return -1;

    const char *fake = [override UTF8String];
    size_t need = strlen(fake) + 1;

    if (oldlenp) {
        if (oldp && *oldlenp >= need) {
            memcpy(oldp, fake, need);
            *oldlenp = need;
        } else {
            *oldlenp = need;
        }
    }
    NSLog(@"[hook] %s ：%@ -> %s", name, orig, fake);
    return 0;
}

// MARK: - 主钩子函数
static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, const void *newp, size_t newlen) {
    NSDictionary *config = configDict();
    // NSString *key = [NSString stringWithUTF8String:name];
    NSLog(@"sysctlbyname - %s oldp: %s, oldlenp: %ld, newp: %s, newlen: %ld", name, (const char *)oldp, *oldlenp, (const char *)newp, newlen);

    // hw.machine
    if (strcmp(name, "hw.machine") == 0) {
        NSString *orig = getOrigSysctlString(name);
        NSString *override = config[@"dModel"];//iPhone13,4
        NSLog(@"sysctlbyname %s %@ -> %@",name, orig, override);
        if (override.length)
            return setSysctlOverride(name, orig, override, oldp, oldlenp);
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    // hw.model
    // if (strcmp(name, "hw.model") == 0) {
    //     NSString *orig = getOrigSysctlString(name);
    //     NSString *override = config[@"hwModel"];
    //     if (override.length)
    //         return setSysctlOverride(name, orig, override, oldp, oldlenp);
    //     return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    // }

    // kern.osproductversion
    if (strcmp(name, "kern.osproductversion") == 0) {
        NSString *orig = getOrigSysctlString(name);
        NSString *override = config[@"osv"];//17.6.1
        NSLog(@"sysctlbyname %s %@ -> %@",name, orig, override);
        if (override.length)
            return setSysctlOverride(name, orig, override, oldp, oldlenp);
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    // kern.osversion
    if (strcmp(name, "kern.osversion") == 0) {
        NSString *orig = getOrigSysctlString(name);
        NSString *override = config[@"osb"];//20B101
        NSLog(@"sysctlbyname %s %@ -> %@",name, orig, override);
        if (override.length)
            return setSysctlOverride(name, orig, override, oldp, oldlenp);
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    // 其他 key，交给原函数
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}


// ---------- WebKit / CFNetwork 内部直接调用来生成 UA 的 ----------
// CFNetworkCopySystemVersionString
static CFStringRef (*orig_CFNetworkCopySystemVersionString)(void) = NULL;
static CFStringRef hook_CFNetworkCopySystemVersionString(void) {
    CFStringRef origValue = NULL;
    if (orig_CFNetworkCopySystemVersionString) {
        origValue = orig_CFNetworkCopySystemVersionString();
    }

    if (origValue && CFGetTypeID(origValue) == CFStringGetTypeID()) {
        NSLog(@"[hook] CFNetworkCopySystemVersionString 原值 = %@", (__bridge NSString *)origValue);
    } else {
        NSLog(@"[hook] CFNetworkCopySystemVersionString 原值 = <nil or non-string>");
    }

    NSDictionary *config = configDict();
    NSString *osv = config[@"osv"];
    if (osv.length) {
        NSLog(@"[hook] CFNetworkCopySystemVersionString 覆盖为 %@", osv);
        return (CFStringRef)CFRetain((__bridge CFStringRef)osv);
    }

    return origValue;
}

// __CFUserAgentString
static CFStringRef (*orig___CFUserAgentString)(void) = NULL;
static CFStringRef hook___CFUserAgentString(void) {
    CFStringRef origValue = NULL;
    if (orig___CFUserAgentString) {
        origValue = orig___CFUserAgentString();
    }

    if (origValue && CFGetTypeID(origValue) == CFStringGetTypeID()) {
        NSLog(@"[hook] __CFUserAgentString 原值 = %@", (__bridge NSString *)origValue);
    } else {
        NSLog(@"[hook] __CFUserAgentString 原值 = <nil or non-string>");
    }

    NSDictionary *config = configDict();
    NSString *osv = config[@"osv"];
    if (osv.length) {
        NSString *fakeUA = [NSString stringWithFormat:@"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X)", osv];
        NSLog(@"[hook] __CFUserAgentString 覆盖为 %@", fakeUA);
        return (CFStringRef)CFRetain((__bridge CFStringRef)fakeUA);
    }
    return origValue;
}



// ---------- NSProcessInfo hooks ----------
static id (*orig_NSProcessInfo_processInfo)(id, SEL) = NULL;
static pid_t (*orig_NSProcessInfo_processIdentifier)(id, SEL) = NULL;
static id (*orig_NSProcessInfo_globallyUniqueString)(id, SEL) = NULL;
static id (*orig_NSProcessInfo_processName)(id, SEL) = NULL;
static id (*orig_NSProcessInfo_environment)(id, SEL) = NULL;
static id (*orig_NSProcessInfo_arguments)(id, SEL) = NULL;
static NSUInteger (*orig_NSProcessInfo_activeProcessorCount)(id, SEL) = NULL;
static unsigned long long (*orig_NSProcessInfo_physicalMemory)(id, SEL) = NULL;
static double (*orig_NSProcessInfo_systemUptime)(id, SEL) = NULL;
static NSOperatingSystemVersion (*orig_NSProcessInfo_operatingSystemVersion)(id, SEL) = NULL;

// --- replacements ---
static id hook_NSProcessInfo_processInfo(id self, SEL _cmd) {
    id obj = orig_NSProcessInfo_processInfo ? orig_NSProcessInfo_processInfo(self, _cmd) : nil;
    NSLog(@"[HOOK] +[NSProcessInfo processInfo] : %p (class: %s)", obj, obj ? object_getClassName(obj) : "NULL");
    return obj;
}

static pid_t hook_NSProcessInfo_processIdentifier(id self, SEL _cmd) {
    pid_t pid = orig_NSProcessInfo_processIdentifier ? orig_NSProcessInfo_processIdentifier(self, _cmd) : 0;
    NSLog(@"[HOOK] -[NSProcessInfo processIdentifier] : %d", (int)pid);
    return pid;
}

static id hook_NSProcessInfo_globallyUniqueString(id self, SEL _cmd) {
    id s = orig_NSProcessInfo_globallyUniqueString ? orig_NSProcessInfo_globallyUniqueString(self, _cmd) : nil;
    NSLog(@"[HOOK] -[NSProcessInfo globallyUniqueString] : %@", s);
    return s;
}

static id hook_NSProcessInfo_processName(id self, SEL _cmd) {
    id n = orig_NSProcessInfo_processName ? orig_NSProcessInfo_processName(self, _cmd) : nil;
    NSLog(@"[HOOK] -[NSProcessInfo processName] : %@", n);
    return n;
}

static id hook_NSProcessInfo_environment(id self, SEL _cmd) {
    id env = orig_NSProcessInfo_environment ? orig_NSProcessInfo_environment(self, _cmd) : nil;
    if ([env isKindOfClass:[NSDictionary class]]) {
        NSDictionary *d = env;
        NSArray *keys = d.allKeys;
        NSUInteger limit = MIN((NSUInteger)10, keys.count);
        NSMutableString *out = [NSMutableString stringWithFormat:@"[HOOK] -[NSProcessInfo environment] count=%lu {", (unsigned long)keys.count];
        for (NSUInteger i = 0; i < limit; i++) {
            [out appendFormat:@"%@=%@;", keys[i], d[keys[i]]];
        }
        if (keys.count > limit) [out appendFormat:@" ...(%lu more)", (unsigned long)(keys.count - limit)];
        [out appendString:@"}"];
        NSLog(@"%@", out);
    } else {
        NSLog(@"[HOOK] -[NSProcessInfo environment] : %@", env);
    }
    return env;
}

static id hook_NSProcessInfo_arguments(id self, SEL _cmd) {
    id arr = orig_NSProcessInfo_arguments ? orig_NSProcessInfo_arguments(self, _cmd) : nil;
    NSLog(@"[HOOK] -[NSProcessInfo arguments] : %@", arr);
    return arr;
}

static NSUInteger hook_NSProcessInfo_activeProcessorCount(id self, SEL _cmd) {
    NSUInteger v = orig_NSProcessInfo_activeProcessorCount ? orig_NSProcessInfo_activeProcessorCount(self, _cmd) : 0;
    NSLog(@"[HOOK] -[NSProcessInfo activeProcessorCount] : %lu", (unsigned long)v);
    return v;
}

static unsigned long long hook_NSProcessInfo_physicalMemory(id self, SEL _cmd) {
    unsigned long long mem = orig_NSProcessInfo_physicalMemory ? orig_NSProcessInfo_physicalMemory(self, _cmd) : 0;
    NSLog(@"[HOOK] -[NSProcessInfo physicalMemory] : %llu bytes", mem);
    return mem;
}

static double hook_NSProcessInfo_systemUptime(id self, SEL _cmd) {
    double up = orig_NSProcessInfo_systemUptime ? orig_NSProcessInfo_systemUptime(self, _cmd) : 0;
    NSLog(@"[HOOK] -[NSProcessInfo systemUptime] : %f s", up);
    return up;
}

static NSOperatingSystemVersion hook_NSProcessInfo_operatingSystemVersion(id self, SEL _cmd) {
    NSOperatingSystemVersion orig = orig_NSProcessInfo_operatingSystemVersion ? orig_NSProcessInfo_operatingSystemVersion(self, _cmd) : (NSOperatingSystemVersion){0,0,0};
    NSDictionary *cfg = configDict();
    NSInteger major = orig.majorVersion;
    NSInteger minor = orig.minorVersion;
    NSInteger patch = orig.patchVersion;

    if ([cfg isKindOfClass:[NSDictionary class]]) {
        NSNumber *mj = cfg[@"os_major"];
        NSNumber *mn = cfg[@"os_minor"];
        NSNumber *pt = cfg[@"os_patch"];
        if (mj) major = mj.integerValue;
        if (mn) minor = mn.integerValue;
        if (pt) patch = pt.integerValue;
    }

    NSLog(@"[HOOK] -[NSProcessInfo operatingSystemVersion] : %ld.%ld.%ld", (long)major, (long)minor, (long)patch);
    NSOperatingSystemVersion v = { major, minor, patch };
    return v;
}



// ---------- NSUserDefaults -setObject:forKey: hook ----------
static NSString *replaceiPhoneOSVersion(NSString *input, NSString *newVer) {
    if (![input isKindOfClass:[NSString class]] || !newVer) return input;
    NSError *err = nil;
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:@"iPhone OS[ _][0-9]+(?:[._][0-9]+)*" options:0 error:&err];
    if (!err) {
        return [re stringByReplacingMatchesInString:input options:0 range:NSMakeRange(0, input.length) withTemplate:[NSString stringWithFormat:@"iPhone OS %@", newVer]];
    }
    return input;
}
// ---------- NSUserDefaults -objectForKey: hook ----------
static id (*orig_NSUserDefaults_objectForKey)(id, SEL, id) = NULL;
static id hook_NSUserDefaults_objectForKey(id self, SEL _cmd, id key) {
    @autoreleasepool {
        NSString *keyStr = [key respondsToSelector:@selector(description)] ? [key description] : nil;
        if (!keyStr) {
            return orig_NSUserDefaults_objectForKey(self, _cmd, key);
        }
        
        // 先获取原始值
        id origValue = orig_NSUserDefaults_objectForKey(self, _cmd, key);
        
        // 处理 Qimei（如果配置中有值，返回配置的值）
        if ([keyStr isEqualToString:@"kTencentStatic_Qimei"]) {
            //原值 {"o16":"11ca09173e0e2c6121e2f5a55354fa88888","o36":"fae0c6104adffedfd37614e500001de19917"}
            NSDictionary *cfg = configDict();
            NSString *newQimei = cfg[@"q36"];
            
            if (newQimei && [newQimei isKindOfClass:[NSString class]] && newQimei.length > 0) {
                // 尝试解析原始值为 JSON 字典
                if ([origValue isKindOfClass:[NSString class]]) {
                    NSData *jsonData = [origValue dataUsingEncoding:NSUTF8StringEncoding];
                    NSError *jsonErr = nil;
                    id jsonObj = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingMutableContainers error:&jsonErr];
                    
                    if (!jsonErr && [jsonObj isKindOfClass:[NSDictionary class]]) {
                        NSMutableDictionary *modifiedDict = (NSMutableDictionary *)jsonObj;
                        modifiedDict[@"o16"] = newQimei;
                        modifiedDict[@"o36"] = newQimei;
                        
                        // 转换回 JSON 字符串
                        NSData *modifiedJsonData = [NSJSONSerialization dataWithJSONObject:modifiedDict options:0 error:&jsonErr];
                        if (!jsonErr && modifiedJsonData) {
                            NSString *modifiedJsonStr = [[NSString alloc] initWithData:modifiedJsonData encoding:NSUTF8StringEncoding];
                            NSLog(@"[HOOK] NSUserDefaults objectForKey: %@: %@ -> %@", keyStr, origValue, modifiedJsonStr);
                            return modifiedJsonStr;
                        }
                    }
                }
                // 如果解析失败，直接返回新值
                NSLog(@"[HOOK] NSUserDefaults objectForKey: %@: 无法解析 JSON，直接替换为 %@", keyStr, newQimei);
                return newQimei;
            }
            // 配置不存在或为空，返回原始值
            return origValue;
        }
        
        // 处理 saveAgent 字典（替换其中的版本号）
        if ([keyStr isEqualToString:@"saveAgent"] && [origValue isKindOfClass:[NSDictionary class]]) {
            NSDictionary *cfg = configDict();
            NSString *osv = cfg[@"osv"];
            if (!osv || ![osv isKindOfClass:[NSString class]]) {
                return origValue;
            }
            
            NSString *newVer = [osv stringByReplacingOccurrencesOfString:@"." withString:@"_"];
            NSMutableDictionary *agentDict = [(NSDictionary *)origValue mutableCopy];
            BOOL changed = NO;
            
            for (NSString *uaKey in @[@"SystemUserAgent", @"UserAgent"]) {
                id uaValue = agentDict[uaKey];
                if ([uaValue isKindOfClass:[NSString class]]) {
                    NSString *newUA = replaceiPhoneOSVersion(uaValue, newVer);
                    if (newUA != uaValue) {
                        agentDict[uaKey] = newUA;
                        changed = YES;
                    }
                }
            }
            
            NSLog(@"[HOOK] NSUserDefaults objectForKey: saveAgent: %@ -> %@",origValue, agentDict);
            if (changed) {
                return [agentDict copy];
            }
            return origValue;
        }
        
        // 处理其他包含 Agent 的 key（字符串）
        if ([keyStr rangeOfString:@"Agent" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            if ([origValue isKindOfClass:[NSString class]]) {
                NSDictionary *cfg = configDict();
                NSString *osv = cfg[@"osv"];
                if (!osv || ![osv isKindOfClass:[NSString class]]) {
                    return origValue;
                }
                
                NSString *newVer = [osv stringByReplacingOccurrencesOfString:@"." withString:@"_"];
                NSString *newValue = replaceiPhoneOSVersion(origValue, newVer);
                if (newValue != origValue) {
                    NSLog(@"[HOOK] NSUserDefaults objectForKey: %@: %@-> %@", keyStr, origValue, newValue);
                    return newValue;
                }
            }
            return origValue;
        }
        
        // 其他情况，返回原始值
        return origValue;
    }
}

// ---------- NSUserDefaults -setObject:forKey: hook ----------
static void (*orig_NSUserDefaults_setObject_forKey)(id, SEL, id, id) = NULL;
static void hook_NSUserDefaults_setObject_forKey(id self, SEL _cmd, id object, id key) {
    @autoreleasepool {
        NSString *keyStr = [key respondsToSelector:@selector(description)] ? [key description] : nil;
        if (!keyStr || !object) {
            orig_NSUserDefaults_setObject_forKey(self, _cmd, object, key);
            return;
        }
        
        // ----- saveAgent 字典 -----
        if ([keyStr isEqualToString:@"saveAgent"] && [object isKindOfClass:[NSDictionary class]]) {
            NSDictionary *cfg = configDict();
            NSString *osv = cfg[@"osv"];
            if (!osv || ![osv isKindOfClass:[NSString class]]) {
                orig_NSUserDefaults_setObject_forKey(self, _cmd, object, key);
                return;
            }
            NSString *newVer = [osv stringByReplacingOccurrencesOfString:@"." withString:@"_"];
            NSMutableDictionary *agentDict = [object mutableCopy];
            for (NSString *uaKey in @[@"SystemUserAgent", @"UserAgent"]) {
                agentDict[uaKey] = replaceiPhoneOSVersion(agentDict[uaKey], newVer);
            }
            orig_NSUserDefaults_setObject_forKey(self, _cmd, agentDict, key);
            return;
        }

        // kTencentStatic_Qimei
        if ([keyStr isEqualToString:@"kTencentStatic_Qimei"]) {
            NSDictionary *cfg = configDict();
            NSString *newQimei = cfg[@"q36"];
            // 只有当配置存在且不为空时才覆盖
            if (newQimei && newQimei.length > 0) {
                // 尝试解析原始值为 JSON 字典
                if ([object isKindOfClass:[NSString class]]) {
                    NSData *jsonData = [object dataUsingEncoding:NSUTF8StringEncoding];
                    NSError *jsonErr = nil;
                    id jsonObj = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingMutableContainers error:&jsonErr];
                    
                    if (!jsonErr && [jsonObj isKindOfClass:[NSDictionary class]]) {
                        NSMutableDictionary *modifiedDict = (NSMutableDictionary *)jsonObj;
                        modifiedDict[@"o16"] = newQimei;
                        modifiedDict[@"o36"] = newQimei;
                        
                        // 转换回 JSON 字符串
                        NSData *modifiedJsonData = [NSJSONSerialization dataWithJSONObject:modifiedDict options:0 error:&jsonErr];
                        if (!jsonErr && modifiedJsonData) {
                            NSString *modifiedJsonStr = [[NSString alloc] initWithData:modifiedJsonData encoding:NSUTF8StringEncoding];
                            NSLog(@"[HOOK] NSUserDefaults setObject:forKey: %@: %@ -> %@", keyStr, object, modifiedJsonStr);
                            orig_NSUserDefaults_setObject_forKey(self, _cmd, modifiedJsonStr, key);
                            return;
                        }
                    }
                }
                // 如果解析失败，直接使用新值
                NSLog(@"[HOOK] NSUserDefaults setObject:forKey: %@: 无法解析 JSON，直接替换为 %@", keyStr, newQimei);
                orig_NSUserDefaults_setObject_forKey(self, _cmd, newQimei, key);
            } else {
                // 配置不存在或为空，使用原值
                orig_NSUserDefaults_setObject_forKey(self, _cmd, object, key);
            }
            return;
        }

        // ----- 其他情况 -----
        orig_NSUserDefaults_setObject_forKey(self, _cmd, object, key);
    }
}




// ========== Hook TMEWebUserAgent -readLocalUserAgentCaches ==========
// 保存原 impl
// static id (*orig_TMEWebUserAgent_readLocalUserAgentCaches)(id, SEL) = NULL;
// static id hook_TMEWebUserAgent_readLocalUserAgentCaches(id self, SEL _cmd) {
//     @autoreleasepool {
//         id orig = nil;
//         if (orig_TMEWebUserAgent_readLocalUserAgentCaches) {
//             orig = orig_TMEWebUserAgent_readLocalUserAgentCaches(self, _cmd);
//         } else {
//             // 没有原 impl，则尽量不影响，返回 nil 或者空字典
//             NSLog(@"[HOOK] orig_TMEWebUserAgent_readLocalUserAgentCaches == NULL");
//             return orig;
//         }

//         if (!orig) {
//             NSLog(@"[HOOK] readLocalUserAgentCaches returned nil");
//             return orig;
//         }

//         // 只处理字典类型
//         if (![orig isKindOfClass:[NSDictionary class]]) {
//             NSLog(@"[HOOK] readLocalUserAgentCaches returned non-dictionary: %@", [orig class]);
//             return orig;
//         }

//         NSMutableDictionary *m = [orig mutableCopy];

//         // 从配置读取目标版本，例如 "16.1.1"
//         NSDictionary *cfg = configDict();
//         NSString *sVersion = nil;
//         if ([cfg isKindOfClass:[NSDictionary class]]) {
//             sVersion = cfg[@"osv"];
//         }
//         if (!sVersion || ![sVersion isKindOfClass:[NSString class]] || sVersion.length == 0) {
//             // 没配置则不改动，返回原始字典
//             NSLog(@"[HOOK] readLocalUserAgentCaches: no osv in config -> no change");
//             return orig;
//         }

//         // 把 "16.1.1" -> "16_1_1" （UA 中使用下划线）
//         NSString *underscored = [sVersion stringByReplacingOccurrencesOfString:@"." withString:@"_"];

//         // 定义替换函数：把 "iPhone OS 16_7_11" 这类片段替换成 "iPhone OS <underscored>"
//         NSRegularExpression *re = nil;
//         NSError *reErr = nil;
//         // 捕获形如 "iPhone OS 16_7" 或 "iPhone OS 16_7_11" 的片段
//         re = [NSRegularExpression regularExpressionWithPattern:@"iPhone OS [0-9]+(?:_[0-9]+)*(?:_[0-9]+)?" options:0 error:&reErr];
//         if (reErr) {
//             NSLog(@"[HOOK] regex error: %@", reErr);
//             // 如果正则失败则还是尝试简单字符串替换 "16_7_11" -> underscored
//         }

//         NSArray<NSString *> *keysToPatch = @[@"SystemUserAgent", @"UserAgent"];
//         BOOL changed = NO;
//         for (NSString *k in keysToPatch) {
//             id v = m[k];
//             if (![v isKindOfClass:[NSString class]]) continue;
//             NSString *s = (NSString *)v;
//             NSString *newS = s;

//             if (re) {
//                 // 用 regex 替换 iPhone OS ... 部分
//                 newS = [re stringByReplacingMatchesInString:newS options:0 range:NSMakeRange(0, newS.length) withTemplate:[NSString stringWithFormat:@"iPhone OS %@", underscored]];
//             } else {
//                 // 回退：直接替换任意已有的数字点或下划线格式（更保守）
//                 // 先把点改成下划线，然后寻找第一个 "iPhone OS " 后的版本并替换
//                 NSRange r = [newS rangeOfString:@"iPhone OS "];
//                 if (r.location != NSNotFound) {
//                     NSUInteger start = r.location + r.length;
//                     // 从 start 找到下一个 " like Mac OS X" 或者 ")" 作为结束
//                     NSRange endRange = [newS rangeOfString:@" like Mac OS X" options:0 range:NSMakeRange(start, newS.length - start)];
//                     NSUInteger end = (endRange.location != NSNotFound) ? endRange.location : newS.length;
//                     NSRange verRange = NSMakeRange(start, end - start);
//                     NSString *ver = [newS substringWithRange:verRange];
//                     // 将点改下划线
//                     NSString *ver2 = [ver stringByReplacingOccurrencesOfString:@"." withString:@"_"];
//                     newS = [newS stringByReplacingCharactersInRange:verRange withString:ver2];
//                     // 之后再替换 ver2 为 underscored（确保一致）
//                     newS = [newS stringByReplacingOccurrencesOfString:ver2 withString:underscored];
//                 }
//             }

//             if (![newS isEqualToString:s]) {
//                 m[k] = newS;
//                 changed = YES;
//                 NSLog(@"[HOOK] patched %@: \n  old: %@\n  new: %@", k, s, newS);
//             } else {
//                 // 即使没有通过 regex 替换，也尝试直接把现有 xxx_xxx_xxx 替换为 underscored（保守替换）
//                 // 匹配形如 \d+_\d+(?:_\d+)?
//                 NSRegularExpression *numRe = [NSRegularExpression regularExpressionWithPattern:@"[0-9]+_[0-9]+(?:_[0-9]+)?" options:0 error:NULL];
//                 if (numRe) {
//                     newS = [numRe stringByReplacingMatchesInString:newS options:0 range:NSMakeRange(0, newS.length) withTemplate:underscored];
//                     if (![newS isEqualToString:s]) {
//                         m[k] = newS;
//                         changed = YES;
//                         NSLog(@"[HOOK] fallback patched %@: \n  old: %@\n  new: %@", k, s, newS);
//                     }
//                 }
//             }
//         }

//         if (changed) {
//             NSDictionary *ret = [m copy];
//             return ret;
//         } else {
//             // 没改动则返回原来的对象（降低副作用）
//             return orig;
//         }
//     }
// }



// ---------- Hook +[NSJSONSerialization dataWithJSONObject:options:error:] ----------
// 注意：Objective-C 方法需要使用 method_setImplementation，fishhook 只能 Hook C 函数
static NSData *(*orig_NSJSONSerialization_dataWithJSONObject_options_error_)(id, SEL, id, NSJSONWritingOptions, NSError **) = NULL;
static NSData *hook_NSJSONSerialization_dataWithJSONObject_options_error_(id self, SEL _cmd, id obj, NSJSONWritingOptions opt, NSError **error) {
    @autoreleasepool {
        // 记录原始调用
        if ([obj isKindOfClass:[NSDictionary class]]) {
            NSDictionary *dict = (NSDictionary *)obj;
            NSLog(@"[HOOK]NSJSONSerialization: 入参: %@: %@", [obj class], dict);
        } else if ([obj isKindOfClass:[NSArray class]]) {
            NSArray *arr = (NSArray *)obj;
            NSLog(@"[HOOK]NSJSONSerialization: 入参: %@: %@", [obj class], arr);
        } else {
            NSLog(@"[HOOK]NSJSONSerialization: 入参: %@", [obj class]);
        }
        
        // 如果入参是字典，可以在这里修改内容
        id modifiedObj = obj;
        if ([obj isKindOfClass:[NSMutableDictionary class]]) {
            // NSMutableDictionary *mutableDict = (NSMutableDictionary *)obj;
            // 可以在这里修改字典内容
            // 例如：mutableDict[@"key"] = @"value";
        } else if ([obj isKindOfClass:[NSDictionary class]]) {
            // 如果不是可变字典，创建可变副本
            // NSMutableDictionary *mutableDict = [(NSDictionary *)obj mutableCopy];
            // 可以在这里修改字典内容
            // 例如：mutableDict[@"key"] = @"value";
            // modifiedObj = mutableDict;
        }
        
        // 调用原始方法
        NSData *result = nil;
        if (orig_NSJSONSerialization_dataWithJSONObject_options_error_) {
            result = orig_NSJSONSerialization_dataWithJSONObject_options_error_(self, _cmd, modifiedObj, opt, error);
        } else {
            // 如果没有原始实现，使用系统方法（不应该发生）
            result = [NSJSONSerialization dataWithJSONObject:modifiedObj options:opt error:error];
        }
        
        return result;
    }
}

// 安装 Hook +[NSJSONSerialization dataWithJSONObject:options:error:]
static void hook_NSJSONSerialization_dataWithJSONObject_options_error_method(void) {
    Class NSJSONSerializationClass = objc_getClass("NSJSONSerialization");
    if (NSJSONSerializationClass) {
        SEL sel = sel_registerName("dataWithJSONObject:options:error:");
        Method m = class_getClassMethod(NSJSONSerializationClass, sel);
        if (m) {
            orig_NSJSONSerialization_dataWithJSONObject_options_error_ = (NSData *(*)(id, SEL, id, NSJSONWritingOptions, NSError **))method_getImplementation(m);
            method_setImplementation(m, (IMP)hook_NSJSONSerialization_dataWithJSONObject_options_error_);
            NSLog(@"[HOOK] ✅[NSJSONSerialization]: +dataWithJSONObject:options:error:");
        } else {
            NSLog(@"[HOOK] ❌[NSJSONSerialization]: +dataWithJSONObject:options:error: 方法未找到");
        }
    } else {
        NSLog(@"[HOOK] ❌[NSJSONSerialization]: 类未找到");
    }
}


// ---------- 安装 swizzle helper ----------
static void swizzle_instance_method(Class cls, SEL sel, IMP newImp, IMP *origImpStorage, const char *types) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (m) {
        // 保存原 impl
        *origImpStorage = (IMP)method_getImplementation(m);
        // 设置新 impl
        method_setImplementation(m, newImp);
    } else {
        // 如果类没有实现该方法，尝试添加
        class_addMethod(cls, sel, newImp, types ?: "v@:");
    }
}

// ---------- 反检测：Hook 常见的防注入检测函数 ----------
// Hook _dyld_image_count 和 _dyld_get_image_name 来隐藏 dylib 注入
static uint32_t (*orig_dyld_image_count)(void) = NULL;
static uint32_t hook_dyld_image_count(void) {
    uint32_t count = orig_dyld_image_count();
    // 可以返回原始值，或者过滤掉我们的 dylib
    return count;
}

static const char* (*orig_dyld_get_image_name)(uint32_t image_index) = NULL;
static const char* hook_dyld_get_image_name(uint32_t image_index) {
    const char* name = orig_dyld_get_image_name(image_index);
    // 如果检测到我们的 dylib 名称，可以返回 NULL 或伪造名称
    if (name && strstr(name, "HookKuGou") != NULL) {
        // 可以选择隐藏或返回原始值
        // return NULL; // 隐藏我们的 dylib
    }
    return name;
}

// Hook dlopen 来隐藏动态库加载
static void* (*orig_dlopen)(const char* path, int mode) = NULL;
static void* hook_dlopen(const char* path, int mode) {
    // 可以记录或过滤某些库的加载
    void* handle = orig_dlopen(path, mode);
    return handle;
}

// Hook sysctl 来隐藏进程信息（如果应用检测进程列表）
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) = NULL;
static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int result = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    // 可以在这里过滤某些进程信息
    return result;
}


// ---------- constructor: 安装所有 hook ----------
__attribute__((constructor))
static void init_hooks(void) {
    @autoreleasepool {
        NSLog(@"[HOOK] init_hooks called");
        // Hook dyld 相关函数（使用 fishhook）
        struct rebinding dyld_rebindings[] = {
            {"_dyld_image_count", (void *)hook_dyld_image_count, (void **)&orig_dyld_image_count},
            {"_dyld_get_image_name", (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
            {"dlopen", (void *)hook_dlopen, (void **)&orig_dlopen},
            {"sysctl", (void *)hook_sysctl, (void **)&orig_sysctl}
        };
        rebind_symbols(dyld_rebindings, 4);
        // fishhook 替换 sysctlbyname
        struct rebinding rbs[3];

        rbs[0].name = "sysctlbyname";
        rbs[0].replacement = (void *)hook_sysctlbyname;
        rbs[0].replaced = (void **)&orig_sysctlbyname;

        // CFNetworkCopySystemVersionString
        rbs[1].name = "CFNetworkCopySystemVersionString";
        rbs[1].replacement = (void *)hook_CFNetworkCopySystemVersionString;
        rbs[1].replaced = (void **)&orig_CFNetworkCopySystemVersionString;

        // __CFUserAgentString
        rbs[2].name = "__CFUserAgentString";
        rbs[2].replacement = (void *)hook___CFUserAgentString;
        rbs[2].replaced = (void **)&orig___CFUserAgentString;

        rebind_symbols(rbs, 3);

        // dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        //     NSDictionary *config = configDict();
        //     NSNumber *scalew = config[@"scalew"];
        //     NSNumber *scaleh = config[@"scaleh"];
        //     CGFloat w = scalew.floatValue;
        //     CGFloat h = scaleh.floatValue;

        //     UIWindow *win = currentWindow();//[UIApplication sharedApplication].keyWindow;
        //     win.transform = CGAffineTransformMakeScale(w, h); // 例如将超出部分缩小
        //     win.center = [UIScreen mainScreen].bounds.origin;
        // });

        // UIDevice
        Class UIDeviceClass = objc_getClass("UIDevice");
        if (UIDeviceClass) {
            swizzle_instance_method(UIDeviceClass, @selector(name), (IMP)hook_UIDevice_name, (IMP *)&orig_UIDevice_name, "@@:");
            swizzle_instance_method(UIDeviceClass, @selector(identifierForVendor), (IMP)hook_UIDevice_identifierForVendor, (IMP *)&orig_UIDevice_identifierForVendor, "@@:");
            swizzle_instance_method(UIDeviceClass, @selector(systemVersion), (IMP)hook_UIDevice_systemVersion, (IMP *)&orig_UIDevice_systemVersion, "@@:");//
        }

        // ASIdentifierManager
        Class ASClass = objc_getClass("ASIdentifierManager");
        if (ASClass) {
            swizzle_instance_method(ASClass, @selector(advertisingIdentifier), (IMP)hook_ASID_advertisingIdentifier, (IMP *)&orig_ASID_advertisingIdentifier, "@@:");
        }

        // UIScreen
        Class UIScreenClass = objc_getClass("UIScreen");
        if (UIScreenClass) {
            swizzle_instance_method(UIScreenClass, @selector(bounds), (IMP)hook_UIScreen_bounds, (IMP *)&orig_UIScreen_bounds, "{CGRect={CGPoint=dd}{CGSize=dd}}@:");
            swizzle_instance_method(UIScreenClass, @selector(scale), (IMP)hook_UIScreen_scale, (IMP *)&orig_UIScreen_scale, "f@:");
            swizzle_instance_method(UIScreenClass, @selector(nativeBounds), (IMP)hook_UIScreen_nativeBounds, (IMP *)&orig_UIScreen_nativeBounds, "{CGRect={CGPoint=dd}{CGSize=dd}}@:");
        }

        // NSURLRequest
        Class NSURLRequestClass = objc_getClass("NSURLRequest");
        if (NSURLRequestClass) {
            swizzle_instance_method(NSURLRequestClass, @selector(allHTTPHeaderFields), (IMP)hook_NSURLRequest_allHTTPHeaderFields, (IMP *)&orig_NSURLRequest_allHTTPHeaderFields, "@@:");
        }

        // NSURLSession
        // Class NSURLSessionClass = objc_getClass("NSURLSession");
        // if (NSURLSessionClass) {
        //     swizzle_instance_method(NSURLSessionClass, @selector(dataTaskWithRequest:completionHandler:), (IMP)hook_NSURLSession_dataTaskWithRequest_completionHandler, (IMP *)&orig_NSURLSession_dataTaskWithRequest_completionHandler, "@@:@?"); // types: id,SEL,NSURLRequest*,block
        // }

        // NSProcessInfo
        Class NSProcessInfoClass = objc_getClass("NSProcessInfo");
        if (NSProcessInfoClass) {
            swizzle_instance_method(NSProcessInfoClass, @selector(processInfo), (IMP)hook_NSProcessInfo_processInfo, (IMP *)&orig_NSProcessInfo_processInfo, "@@:");
            swizzle_instance_method(NSProcessInfoClass, @selector(processIdentifier), (IMP)hook_NSProcessInfo_processIdentifier, (IMP *)&orig_NSProcessInfo_processIdentifier, "i@:");
            swizzle_instance_method(NSProcessInfoClass, @selector(globallyUniqueString), (IMP)hook_NSProcessInfo_globallyUniqueString, (IMP *)&orig_NSProcessInfo_globallyUniqueString, "@@:");
            swizzle_instance_method(NSProcessInfoClass, @selector(processName), (IMP)hook_NSProcessInfo_processName, (IMP *)&orig_NSProcessInfo_processName, "@@:");
            swizzle_instance_method(NSProcessInfoClass, @selector(environment), (IMP)hook_NSProcessInfo_environment, (IMP *)&orig_NSProcessInfo_environment, "@@:");
            swizzle_instance_method(NSProcessInfoClass, @selector(arguments), (IMP)hook_NSProcessInfo_arguments, (IMP *)&orig_NSProcessInfo_arguments, "@@:");
            swizzle_instance_method(NSProcessInfoClass, @selector(activeProcessorCount), (IMP)hook_NSProcessInfo_activeProcessorCount, (IMP *)&orig_NSProcessInfo_activeProcessorCount, "Q@:");
            swizzle_instance_method(NSProcessInfoClass, @selector(physicalMemory), (IMP)hook_NSProcessInfo_physicalMemory, (IMP *)&orig_NSProcessInfo_physicalMemory, "Q@:");
            swizzle_instance_method(NSProcessInfoClass, @selector(systemUptime), (IMP)hook_NSProcessInfo_systemUptime, (IMP *)&orig_NSProcessInfo_systemUptime, "d@:");
            swizzle_instance_method(NSProcessInfoClass, @selector(operatingSystemVersion), (IMP)hook_NSProcessInfo_operatingSystemVersion, (IMP *)&orig_NSProcessInfo_operatingSystemVersion, "{_NSOperatingSystemVersion=iii}@:");
        }

        // StatisticInfo +sysVer
        Class StatisticInfoClass = objc_getClass("StatisticInfo");
        if (StatisticInfoClass) {
            Method m = class_getClassMethod(StatisticInfoClass, @selector(sysVer));
            if (m) {
                orig_StatisticInfo_sysVer = (id (*)(id, SEL))method_getImplementation(m);
                method_setImplementation(m, (IMP)hook_StatisticInfo_sysVer);
                NSLog(@"[HOOK] hooked +[StatisticInfo sysVer]");
            } else {
                NSLog(@"[HOOK] +sysVer method not found");
            }
            
            // StatisticInfo +udid
            Method m2 = class_getClassMethod(StatisticInfoClass, @selector(udid));
            if (m2) {
                orig_StatisticInfo_udid = (id (*)(id, SEL))method_getImplementation(m2);
                method_setImplementation(m2, (IMP)hook_StatisticInfo_udid);
                NSLog(@"[HOOK] ✅ hooked +[StatisticInfo udid]");
            } else {
                NSLog(@"[HOOK] ❌ +[StatisticInfo udid] method not found");
            }
        }

        // KGTencentStatistics -q36
        Class KGTencentStatisticsClass = objc_getClass("KGTencentStatistics");
        if (KGTencentStatisticsClass) {
            SEL sel = sel_registerName("q36");
            Method m = class_getInstanceMethod(KGTencentStatisticsClass, sel);
            if (m) {
                orig_KGTencentStatistics_q36 = (NSString *(*)(id, SEL))method_getImplementation(m);
                method_setImplementation(m, (IMP)hook_KGTencentStatistics_q36);
                NSLog(@"[HOOK] ✅ hooked -[KGTencentStatistics q36]");
            } else {
                NSLog(@"[HOOK] ❌ -[KGTencentStatistics q36] method not found");
            }
        } else {
            NSLog(@"[HOOK] ❌ KGTencentStatistics class not found");
        }

        // TDeviceInfoUtil -GetQIMEI:
        Class TDeviceInfoUtilClass = objc_getClass("TDeviceInfoUtil");
        if (TDeviceInfoUtilClass) {
            SEL sel = sel_registerName("GetQIMEI:");
            Method m = class_getInstanceMethod(TDeviceInfoUtilClass, sel);
            if (m) {
                orig_TDeviceInfoUtil_GetQIMEI_ = (id (*)(id, SEL, id))method_getImplementation(m);
                method_setImplementation(m, (IMP)hook_TDeviceInfoUtil_GetQIMEI_);
                NSLog(@"[HOOK] ✅ hooked -[TDeviceInfoUtil GetQIMEI:]");
            } else {
                NSLog(@"[HOOK] ❌ -[TDeviceInfoUtil GetQIMEI:] method not found");
            }
        } else {
            NSLog(@"[HOOK] ❌ TDeviceInfoUtil class not found");
        }

        // ZBHObjectFloatContent -uid
        Class ZBHObjectFloatContentClass = objc_getClass("ZBHObjectFloatContent");
        if (ZBHObjectFloatContentClass) {
            SEL sel = sel_registerName("uid");
            Method m = class_getInstanceMethod(ZBHObjectFloatContentClass, sel);
            if (m) {
                orig_ZBHObjectFloatContent_uid = (id (*)(id, SEL))method_getImplementation(m);
                method_setImplementation(m, (IMP)hook_ZBHObjectFloatContent_uid);
                NSLog(@"[HOOK] ✅ hooked -[ZBHObjectFloatContent uid]");
            } else {
                NSLog(@"[HOOK] ❌ -[ZBHObjectFloatContent uid] method not found");
            }
        } else {
            NSLog(@"[HOOK] ❌ ZBHObjectFloatContent class not found");
        }

        // NeeFileCache -objectForKey: 和 -objectForKeyedSubscript:
        // 注意：objectForKeyedSubscript: 是 thunk，实际调用 objectForKey:
        // 所以应该优先 hook objectForKey:，这是实际执行逻辑的地方
        Class NeeFileCacheClass = objc_getClass("NeeFileCache");
        if (NeeFileCacheClass) {
            NSLog(@"[HOOK] ✅ NeeFileCache class found: %p", NeeFileCacheClass);
            
            // Hook objectForKey: (实际执行逻辑的方法)
            SEL objectForKeySel = sel_registerName("objectForKey:");
            Method objectForKeyMethod = class_getInstanceMethod(NeeFileCacheClass, objectForKeySel);
            if (objectForKeyMethod) {
                orig_NeeFileCache_objectForKey_ = (id (*)(id, SEL, id))method_getImplementation(objectForKeyMethod);
                method_setImplementation(objectForKeyMethod, (IMP)hook_NeeFileCache_objectForKey_);
                NSLog(@"[HOOK] ✅ hooked -[NeeFileCache objectForKey:] (实际实现)");
            } else {
                NSLog(@"[HOOK] ❌ -[NeeFileCache objectForKey:] method not found");
            }
            
            // Hook objectForKeyedSubscript: (thunk，可选，用于兼容)
            SEL objectForKeyedSubscriptSel = sel_registerName("objectForKeyedSubscript:");
            Method objectForKeyedSubscriptMethod = class_getInstanceMethod(NeeFileCacheClass, objectForKeyedSubscriptSel);
            if (objectForKeyedSubscriptMethod) {
                orig_NeeFileCache_objectForKeyedSubscript_ = (id (*)(id, SEL, id))method_getImplementation(objectForKeyedSubscriptMethod);
                method_setImplementation(objectForKeyedSubscriptMethod, (IMP)hook_NeeFileCache_objectForKeyedSubscript_);
                NSLog(@"[HOOK] ✅ hooked -[NeeFileCache objectForKeyedSubscript:] (thunk)");
            } 
        } 

        // NSUserDefaults
        Class NSUserDefaultsClass = objc_getClass("NSUserDefaults");
        if (NSUserDefaultsClass){
            swizzle_instance_method(NSUserDefaultsClass, @selector(objectForKey:), (IMP)hook_NSUserDefaults_objectForKey, (IMP *)&orig_NSUserDefaults_objectForKey, "@@:@");
            swizzle_instance_method(NSUserDefaultsClass, @selector(setObject:forKey:), (IMP)hook_NSUserDefaults_setObject_forKey, (IMP *)&orig_NSUserDefaults_setObject_forKey, "@@:@");
        }
        //主动调用一次hook_NSUserDefaults_setObject_forKey// kTencentStatic_Qimei
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        [defaults setObject:@"" forKey:@"q36"];
        [defaults synchronize];

        // TMEWebUserAgent
        // Class TMEWebUserAgentClass = objc_getClass("TMEWebUserAgent");
        // if (TMEWebUserAgentClass) {
        //     swizzle_instance_method(TMEWebUserAgentClass, @selector(readLocalUserAgentCaches), (IMP)hook_TMEWebUserAgent_readLocalUserAgentCaches, (IMP *)&orig_TMEWebUserAgent_readLocalUserAgentCaches, "@@:");
        //     NSLog(@"[HOOK] hooked -[TMEWebUserAgent readLocalUserAgentCaches]");
        // }

        // Hook +[NSJSONSerialization dataWithJSONObject:options:error:]
        hook_NSJSONSerialization_dataWithJSONObject_options_error_method();

        NSLog(@"[HOOK] hooks installed");
        
        // 延迟扫描 qimei36 相关方法，等待所有类加载完成
        // dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        //     scanAndHookQimei36Methods();
        // });
    }
}