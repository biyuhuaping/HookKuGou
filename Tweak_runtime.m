// Tweak_runtime.m
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import "fishhook.h"

// ---------- 配置读取 ----------
static NSDictionary *configDict(void) {
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/.deviceFakeConfig.plist"];
    NSURL *url = [NSURL fileURLWithPath:path];
    NSDictionary *dic = [NSDictionary dictionaryWithContentsOfURL:url];
    if (!dic) {
        NSLog(@"[HOOK] Failed to load plist at %@", path);
        dic = @{};
    }
    NSLog(@"[configDict] path at %@", path);
    return dic[@"config"];
}

// ---------- 工具：获取顶层控制器（兼容 Scene） ----------
static UIWindow *currentWindow(void) {
    UIWindow *keyWindow = nil;

    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive &&
                [scene isKindOfClass:[UIWindowScene class]]) {

                UIWindowScene *windowScene = (UIWindowScene *)scene;
                for (UIWindow *window in windowScene.windows) {
                    if (window.windowLevel == UIWindowLevelNormal &&
                        !window.hidden &&
                        window.bounds.size.width > 0 &&
                        window.bounds.size.height > 0) {
                        keyWindow = window;
                        break;
                    }
                }
                if (keyWindow) break;
            }
        }
    }

    if (!keyWindow) {
        for (UIWindow *window in [UIApplication sharedApplication].windows) {
            if (window.windowLevel == UIWindowLevelNormal &&
                !window.hidden &&
                window.bounds.size.width > 0 &&
                window.bounds.size.height > 0) {
                keyWindow = window;
                break;
            }
        }
    }

    if (!keyWindow) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        keyWindow = [UIApplication sharedApplication].keyWindow;
#pragma clang diagnostic pop
    }

    return keyWindow;
}


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
        NSLog(@"[HOOK] UIDevice.name original: %@ => %@", origValue, name);
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
        NSLog(@"[HOOK] idfv override: %@", u.UUIDString);
        return u;
    }
    NSLog(@"[HOOK] idfv original: %@", orig.UUIDString);
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
        NSLog(@"[HOOK] UIDevice.systemVersion original: %@ => %@", origValue, sVersion);
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
    NSLog(@"[Hook] UIScreen.bounds = %.0f x %.0f", value.size.width, value.size.height);

    NSDictionary *config = configDict();
    NSNumber *dx = config[@"dx"];
    NSNumber *dy = config[@"dy"];
    if ([dx isKindOfClass:[NSNumber class]] && [dy isKindOfClass:[NSNumber class]]) {
        CGFloat w = dx.floatValue;
        CGFloat h = dy.floatValue;
        NSLog(@"[Hook] UIScreen.bounds修改为: %.0f x %.0f", w, h);
        return CGRectMake(0, 0, w, h);
    }
    return value;
}

static CGFloat (*orig_UIScreen_scale)(id, SEL) = NULL;
static CGFloat hook_UIScreen_scale(id self, SEL _cmd) {
    CGFloat value = orig_UIScreen_scale(self, _cmd);
    NSDictionary *config = configDict();
    NSNumber *configScale = config[@"scale"];
    if ([configScale isKindOfClass:[NSNumber class]]) {
        NSLog(@"[Hook] override scale: %f", configScale.floatValue);
        return configScale.floatValue;
    }
    return value;
}

static CGRect (*orig_UIScreen_nativeBounds)(id, SEL) = NULL;
static CGRect hook_UIScreen_nativeBounds(id self, SEL _cmd) {
    CGRect value = orig_UIScreen_nativeBounds(self, _cmd);
    NSLog(@"[Hook] UIScreen.nativeBounds = %.0f x %.0f", value.size.width, value.size.height);
    NSDictionary *config = configDict();
    NSNumber *ndx = config[@"ndx"];
    NSNumber *ndy = config[@"ndy"];
    if ([ndx isKindOfClass:[NSNumber class]] && [ndy isKindOfClass:[NSNumber class]]) {
        CGFloat w = ndx.floatValue;
        CGFloat h = ndy.floatValue;
        NSLog(@"[Hook] UIScreen.nativeBounds 修改为: %.0f x %.0f", w, h);
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

    char *buf = malloc(size);
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
    NSLog(@"[hook] %s ：%@ => %s", name, orig, fake);
    return 0;
}

// MARK: - 主钩子函数
static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, const void *newp, size_t newlen) {
    NSDictionary *config = configDict();
    // NSString *key = [NSString stringWithUTF8String:name];

    // hw.machine
    if (strcmp(name, "hw.machine") == 0) {
        NSString *orig = getOrigSysctlString(name);
        NSString *override = config[@"dModel"];//iPhone13,4
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
        if (override.length)
            return setSysctlOverride(name, orig, override, oldp, oldlenp);
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    // kern.osversion
    if (strcmp(name, "kern.osversion") == 0) {
        NSString *orig = getOrigSysctlString(name);
        NSString *override = config[@"osb"];//20B101
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
        return CFRetain((__bridge CFStringRef)osv);
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
        return CFRetain((__bridge CFStringRef)fakeUA);
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
    NSLog(@"[HOOK] +[NSProcessInfo processInfo] => %p (class: %s)", obj, obj ? object_getClassName(obj) : "NULL");
    return obj;
}

static pid_t hook_NSProcessInfo_processIdentifier(id self, SEL _cmd) {
    pid_t pid = orig_NSProcessInfo_processIdentifier ? orig_NSProcessInfo_processIdentifier(self, _cmd) : 0;
    NSLog(@"[HOOK] -[NSProcessInfo processIdentifier] => %d", (int)pid);
    return pid;
}

static id hook_NSProcessInfo_globallyUniqueString(id self, SEL _cmd) {
    id s = orig_NSProcessInfo_globallyUniqueString ? orig_NSProcessInfo_globallyUniqueString(self, _cmd) : nil;
    NSLog(@"[HOOK] -[NSProcessInfo globallyUniqueString] => %@", s);
    return s;
}

static id hook_NSProcessInfo_processName(id self, SEL _cmd) {
    id n = orig_NSProcessInfo_processName ? orig_NSProcessInfo_processName(self, _cmd) : nil;
    NSLog(@"[HOOK] -[NSProcessInfo processName] => %@", n);
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
        NSLog(@"[HOOK] -[NSProcessInfo environment] => %@", env);
    }
    return env;
}

static id hook_NSProcessInfo_arguments(id self, SEL _cmd) {
    id arr = orig_NSProcessInfo_arguments ? orig_NSProcessInfo_arguments(self, _cmd) : nil;
    NSLog(@"[HOOK] -[NSProcessInfo arguments] => %@", arr);
    return arr;
}

static NSUInteger hook_NSProcessInfo_activeProcessorCount(id self, SEL _cmd) {
    NSUInteger v = orig_NSProcessInfo_activeProcessorCount ? orig_NSProcessInfo_activeProcessorCount(self, _cmd) : 0;
    NSLog(@"[HOOK] -[NSProcessInfo activeProcessorCount] => %lu", (unsigned long)v);
    return v;
}

static unsigned long long hook_NSProcessInfo_physicalMemory(id self, SEL _cmd) {
    unsigned long long mem = orig_NSProcessInfo_physicalMemory ? orig_NSProcessInfo_physicalMemory(self, _cmd) : 0;
    NSLog(@"[HOOK] -[NSProcessInfo physicalMemory] => %llu bytes", mem);
    return mem;
}

static double hook_NSProcessInfo_systemUptime(id self, SEL _cmd) {
    double up = orig_NSProcessInfo_systemUptime ? orig_NSProcessInfo_systemUptime(self, _cmd) : 0;
    NSLog(@"[HOOK] -[NSProcessInfo systemUptime] => %f s", up);
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

    NSLog(@"[HOOK] -[NSProcessInfo operatingSystemVersion] => %ld.%ld.%ld", (long)major, (long)minor, (long)patch);
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
static void (*orig_NSUserDefaults_setObject_forKey)(id, SEL, id, id) = NULL;
static void hook_NSUserDefaults_setObject_forKey(id self, SEL _cmd, id object, id key) {
    @autoreleasepool {
        NSString *keyStr = [key respondsToSelector:@selector(description)] ? [key description] : nil;
        if (!keyStr || !object) {
            orig_NSUserDefaults_setObject_forKey(self, _cmd, object, key);
            return;
        }

        NSDictionary *cfg = configDict();
        NSString *osv = cfg[@"osv"];
        if (!osv || ![osv isKindOfClass:[NSString class]]) {
            orig_NSUserDefaults_setObject_forKey(self, _cmd, object, key);
            return;
        }

        NSString *newVer = [osv stringByReplacingOccurrencesOfString:@"." withString:@"_"];

        // ----- saveAgent 字典 -----
        if ([keyStr isEqualToString:@"saveAgent"] && [object isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary *agentDict = [object mutableCopy];
            for (NSString *uaKey in @[@"SystemUserAgent", @"UserAgent"]) {
                agentDict[uaKey] = replaceiPhoneOSVersion(agentDict[uaKey], newVer);
            }
            NSLog(@"[HOOK] NSUserDefaults saveAgent replaced: %@", agentDict);
            orig_NSUserDefaults_setObject_forKey(self, _cmd, agentDict, key);
            return;
        }

        // ----- 其他包含 Agent 的 key -----
        if ([keyStr rangeOfString:@"Agent" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            id newObject = object;
            if ([object isKindOfClass:[NSString class]]) {
                newObject = replaceiPhoneOSVersion(object, newVer);
                if (newObject != object) {
                    NSLog(@"[HOOK] NSUserDefaults setObject for %@ replaced: %@", keyStr, newObject);
                }
            }
            orig_NSUserDefaults_setObject_forKey(self, _cmd, newObject, key);
            return;
        }

        // ----- 其他情况 -----
        orig_NSUserDefaults_setObject_forKey(self, _cmd, object, key);
    }
}




// ========== Hook TMEWebUserAgent -readLocalUserAgentCaches ==========
// 保存原 impl
static id (*orig_TMEWebUserAgent_readLocalUserAgentCaches)(id, SEL) = NULL;
static id hook_TMEWebUserAgent_readLocalUserAgentCaches(id self, SEL _cmd) {
    @autoreleasepool {
        id orig = nil;
        if (orig_TMEWebUserAgent_readLocalUserAgentCaches) {
            orig = orig_TMEWebUserAgent_readLocalUserAgentCaches(self, _cmd);
        } else {
            // 没有原 impl，则尽量不影响，返回 nil 或者空字典
            NSLog(@"[HOOK] orig_TMEWebUserAgent_readLocalUserAgentCaches == NULL");
            return orig;
        }

        if (!orig) {
            NSLog(@"[HOOK] readLocalUserAgentCaches returned nil");
            return orig;
        }

        // 只处理字典类型
        if (![orig isKindOfClass:[NSDictionary class]]) {
            NSLog(@"[HOOK] readLocalUserAgentCaches returned non-dictionary: %@", [orig class]);
            return orig;
        }

        NSMutableDictionary *m = [orig mutableCopy];

        // 从配置读取目标版本，例如 "16.1.1"
        NSDictionary *cfg = configDict();
        NSString *sVersion = nil;
        if ([cfg isKindOfClass:[NSDictionary class]]) {
            sVersion = cfg[@"osv"];
        }
        if (!sVersion || ![sVersion isKindOfClass:[NSString class]] || sVersion.length == 0) {
            // 没配置则不改动，返回原始字典
            NSLog(@"[HOOK] readLocalUserAgentCaches: no osv in config -> no change");
            return orig;
        }

        // 把 "16.1.1" -> "16_1_1" （UA 中使用下划线）
        NSString *underscored = [sVersion stringByReplacingOccurrencesOfString:@"." withString:@"_"];

        // 定义替换函数：把 "iPhone OS 16_7_11" 这类片段替换成 "iPhone OS <underscored>"
        NSRegularExpression *re = nil;
        NSError *reErr = nil;
        // 捕获形如 "iPhone OS 16_7" 或 "iPhone OS 16_7_11" 的片段
        re = [NSRegularExpression regularExpressionWithPattern:@"iPhone OS [0-9]+(?:_[0-9]+)*(?:_[0-9]+)?" options:0 error:&reErr];
        if (reErr) {
            NSLog(@"[HOOK] regex error: %@", reErr);
            // 如果正则失败则还是尝试简单字符串替换 "16_7_11" -> underscored
        }

        NSArray<NSString *> *keysToPatch = @[@"SystemUserAgent", @"UserAgent"];
        BOOL changed = NO;
        for (NSString *k in keysToPatch) {
            id v = m[k];
            if (![v isKindOfClass:[NSString class]]) continue;
            NSString *s = (NSString *)v;
            NSString *newS = s;

            if (re) {
                // 用 regex 替换 iPhone OS ... 部分
                newS = [re stringByReplacingMatchesInString:newS options:0 range:NSMakeRange(0, newS.length) withTemplate:[NSString stringWithFormat:@"iPhone OS %@", underscored]];
            } else {
                // 回退：直接替换任意已有的数字点或下划线格式（更保守）
                // 先把点改成下划线，然后寻找第一个 "iPhone OS " 后的版本并替换
                NSRange r = [newS rangeOfString:@"iPhone OS "];
                if (r.location != NSNotFound) {
                    NSUInteger start = r.location + r.length;
                    // 从 start 找到下一个 " like Mac OS X" 或者 ")" 作为结束
                    NSRange endRange = [newS rangeOfString:@" like Mac OS X" options:0 range:NSMakeRange(start, newS.length - start)];
                    NSUInteger end = (endRange.location != NSNotFound) ? endRange.location : newS.length;
                    NSRange verRange = NSMakeRange(start, end - start);
                    NSString *ver = [newS substringWithRange:verRange];
                    // 将点改下划线
                    NSString *ver2 = [ver stringByReplacingOccurrencesOfString:@"." withString:@"_"];
                    newS = [newS stringByReplacingCharactersInRange:verRange withString:ver2];
                    // 之后再替换 ver2 为 underscored（确保一致）
                    newS = [newS stringByReplacingOccurrencesOfString:ver2 withString:underscored];
                }
            }

            if (![newS isEqualToString:s]) {
                m[k] = newS;
                changed = YES;
                NSLog(@"[HOOK] patched %@: \n  old: %@\n  new: %@", k, s, newS);
            } else {
                // 即使没有通过 regex 替换，也尝试直接把现有 xxx_xxx_xxx 替换为 underscored（保守替换）
                // 匹配形如 \d+_\d+(?:_\d+)?
                NSRegularExpression *numRe = [NSRegularExpression regularExpressionWithPattern:@"[0-9]+_[0-9]+(?:_[0-9]+)?" options:0 error:NULL];
                if (numRe) {
                    newS = [numRe stringByReplacingMatchesInString:newS options:0 range:NSMakeRange(0, newS.length) withTemplate:underscored];
                    if (![newS isEqualToString:s]) {
                        m[k] = newS;
                        changed = YES;
                        NSLog(@"[HOOK] fallback patched %@: \n  old: %@\n  new: %@", k, s, newS);
                    }
                }
            }
        }

        if (changed) {
            NSDictionary *ret = [m copy];
            return ret;
        } else {
            // 没改动则返回原来的对象（降低副作用）
            return orig;
        }
    }
}






// ---------- 安装 swizzle helper ----------
static void swizzle_instance_method(Class cls, SEL sel, IMP newImp, IMP *origImpStorage, const char *types) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (m) {
        // 保存原 impl
        *origImpStorage = (void *)method_getImplementation(m);
        // 设置新 impl
        method_setImplementation(m, newImp);
    } else {
        // 如果类没有实现该方法，尝试添加
        class_addMethod(cls, sel, newImp, types ?: "v@:");
    }
}

// ---------- constructor: 安装所有 hook ----------
__attribute__((constructor))
static void init_hooks(void) {
    @autoreleasepool {
        NSLog(@"[HOOK] init_hooks called");
        // fishhook 替换 sysctlbyname
        struct rebinding rbs[3];

        rbs[0].name = "sysctlbyname";
        rbs[0].replacement = (void *)hook_sysctlbyname;
        rbs[0].replaced = (void *)&orig_sysctlbyname;

        // CFNetworkCopySystemVersionString
        rbs[1].name = "CFNetworkCopySystemVersionString";
        rbs[1].replacement = (void *)hook_CFNetworkCopySystemVersionString;
        rbs[1].replaced = (void *)&orig_CFNetworkCopySystemVersionString;

        // __CFUserAgentString
        rbs[2].name = "__CFUserAgentString";
        rbs[2].replacement = (void *)hook___CFUserAgentString;
        rbs[2].replaced = (void *)&orig___CFUserAgentString;

        rebind_symbols(rbs, 3);

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            NSDictionary *config = configDict();
            NSNumber *scalew = config[@"scalew"];
            NSNumber *scaleh = config[@"scaleh"];
            CGFloat w = scalew.floatValue;
            CGFloat h = scaleh.floatValue;

            UIWindow *win = currentWindow();//[UIApplication sharedApplication].keyWindow;
            win.transform = CGAffineTransformMakeScale(w, h); // 例如将超出部分缩小
            win.center = [UIScreen mainScreen].bounds.origin;
        });

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
                orig_StatisticInfo_sysVer = (void *)method_getImplementation(m);
                method_setImplementation(m, (IMP)hook_StatisticInfo_sysVer);
                NSLog(@"[HOOK] hooked +[StatisticInfo sysVer]");
            } else {
                NSLog(@"[HOOK] +sysVer method not found");
            }
        }

        // NSUserDefaults
        Class NSUserDefaultsClass = objc_getClass("NSUserDefaults");
        if (NSUserDefaultsClass){
            swizzle_instance_method(NSUserDefaultsClass, @selector(setObject:forKey:), (IMP)hook_NSUserDefaults_setObject_forKey, (IMP *)&orig_NSUserDefaults_setObject_forKey, "@@:@");
        }

        // TMEWebUserAgent
        Class TMEWebUserAgentClass = objc_getClass("TMEWebUserAgent");
        if (TMEWebUserAgentClass) {
            swizzle_instance_method(TMEWebUserAgentClass, @selector(readLocalUserAgentCaches), (IMP)hook_TMEWebUserAgent_readLocalUserAgentCaches, (IMP *)&orig_TMEWebUserAgent_readLocalUserAgentCaches, "@@:");
            NSLog(@"[HOOK] hooked -[TMEWebUserAgent readLocalUserAgentCaches]");
        }

        NSLog(@"[HOOK] hooks installed");
    }
}