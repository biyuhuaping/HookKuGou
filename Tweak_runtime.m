// Tweak_runtime.m
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// fishhook header (你需要把 fishhook 源加入工程)
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

// ---------- 辅助函数 ----------
// static id safe_objc_msgSend_id(id target, SEL sel) {
//     if (!target) return nil;
//     IMP imp = class_getMethodImplementation(object_getClass(target), sel);
//     if (!imp) return nil;
//     id (*fn)(id, SEL) = (void *)imp;
//     return fn(target, sel);
// }

// ---------- UIDevice identifierForVendor / systemVersion / model ----------
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

static NSString *(*orig_UIDevice_systemVersion)(id, SEL) = NULL;
static NSString *hook_UIDevice_systemVersion(id self, SEL _cmd) {
    NSDictionary *config = configDict();
    NSString *sVersion = config[@"osv"];
    if (sVersion.length) {
        NSLog(@"[HOOK] systemVersion override: %@", sVersion);
        return sVersion;
    }
    return orig_UIDevice_systemVersion(self, _cmd);
}

static NSString *(*orig_UIDevice_model)(id, SEL) = NULL;
static NSString *hook_UIDevice_model(id self, SEL _cmd) {
    NSDictionary *config = configDict();
    NSString *modelStr = config[@"dModel"];
    if (modelStr.length) {
        NSLog(@"[HOOK] model override: %@", modelStr);
        return modelStr;
    }
    return orig_UIDevice_model(self, _cmd);
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

// ---------- NSURLRequest allHTTPHeaderFields ----------
static NSDictionary *(*orig_NSURLRequest_allHTTPHeaderFields)(id, SEL) = NULL;
static NSDictionary *hook_NSURLRequest_allHTTPHeaderFields(id self, SEL _cmd) {
    NSDictionary *orig = orig_NSURLRequest_allHTTPHeaderFields(self, _cmd);
    NSMutableDictionary *headers = orig ? [orig mutableCopy] : [NSMutableDictionary dictionary];
    NSLog(@"[Hook] User-Agent original: %@", headers);
    return headers;
}

// ---------- NSURLSession dataTaskWithRequest:completionHandler: ----------
static NSURLSessionDataTask *(*orig_NSURLSession_dataTaskWithRequest_completionHandler)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)) = NULL;
static NSURLSessionDataTask *hook_NSURLSession_dataTaskWithRequest_completionHandler(id self, SEL _cmd, NSURLRequest *request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *)) {
    NSString *url = request.URL.absoluteString;
    NSLog(@"[hook] RequestURL: %@", url);
    __block NSString *requestBody = nil;
    if (request.HTTPBody) {
        requestBody = [[NSString alloc] initWithData:request.HTTPBody encoding:NSUTF8StringEncoding];
        NSLog(@"[hook] Request Body: %@", requestBody);
    }
    void (^customCompletion)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSString *responseBody = @"<nil>";
        if (data) {
            NSString *tmp = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (tmp) responseBody = tmp;
        }
        NSLog(@"[hook] 请求：%@\n入参：%@\n出参：%@", url, requestBody, responseBody);
        if (completionHandler) completionHandler(data, response, error);
    };
    return orig_NSURLSession_dataTaskWithRequest_completionHandler(self, _cmd, request, customCompletion);
}

// ---------- NSBundle infoDictionary ----------
static NSDictionary *(*orig_NSBundle_infoDictionary)(id, SEL) = NULL;
static NSDictionary *hook_NSBundle_infoDictionary(id self, SEL _cmd) {
    NSDictionary *originalDict = orig_NSBundle_infoDictionary(self, _cmd);
    if (!originalDict) return originalDict;
    NSMutableDictionary *mutableDict = [originalDict mutableCopy];
    NSDictionary *config = configDict();
    NSString *fakeOS = config[@"osv"];
    if (fakeOS && mutableDict[@"DTPlatformVersion"]) {
        NSLog(@"[HOOK] override DTPlatformVersion: %@，%@", fakeOS, mutableDict);
        mutableDict[@"DTPlatformVersion"] = fakeOS;
    }
    return [mutableDict copy];
}

// ---------- sysctlbyname via fishhook ----------

static int (*orig_sysctlbyname)(const char *, void *, size_t *, const void *, size_t) = NULL;
// 读取 sysctlbyname 原始字符串
static NSString *getOrigSysctlString(const char *name) {
    size_t size = 0;
    if (orig_sysctlbyname(name, NULL, &size, NULL, 0) != 0 || size == 0) {
        return nil;
    }
    char *buf = malloc(size);
    if (!buf) return nil;
    if (orig_sysctlbyname(name, buf, &size, NULL, 0) != 0) {
        free(buf);
        return nil;
    }
    NSString *val = [NSString stringWithUTF8String:buf];
    free(buf);
    NSLog(@"[hook] sysctlbyname： %s 原值： %@", name, val);
    return val;
}
static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, const void *newp, size_t newlen) {
    NSDictionary *config = configDict();

    // hw.machine
    if (strcmp(name, "hw.machine") == 0) {
        getOrigSysctlString("hw.machine");//iPhone10,5
        NSString *override = config[@"dModel"];
        if (override) {//有配置才覆盖，没有配置 → 走原始逻辑
            const char *machine1 = [override UTF8String];
            size_t need = strlen(machine1) + 1;
            if (oldp && oldlenp) {
                if (*oldlenp >= need) {
                    memcpy(oldp, machine1, need);
                    *oldlenp = need;
                } else {
                    *oldlenp = need; // buffer 不够，只返回长度
                }
            }
            NSLog(@"[hook] hw.machine 修改为： %s", machine1);
            return 0;
        }
    }

    // hw.model
    else if (strcmp(name, "hw.model") == 0) {
        getOrigSysctlString("hw.model");//D211AP
        NSString *override = config[@"hwModel"];
        if (override) {//有配置才覆盖，没有配置 → 走原始逻辑
            const char *model1 = [override UTF8String];
            size_t need = strlen(model1) + 1;
            if (oldp && oldlenp) {
                if (*oldlenp >= need) {
                    memcpy(oldp, model1, need);
                    *oldlenp = need;
                } else {
                    *oldlenp = need;
                }
            }
            NSLog(@"[hook] hw.model 修改为： %s", model1);
            return 0;
        }
    }

    // kern.osproductversion
    else if (strcmp(name, "kern.osproductversion") == 0) {
        getOrigSysctlString("kern.osproductversion");
        NSDictionary *config = configDict();
        NSString *osv = config[@"osv"];  // "17.6.1"
        if (osv) { //有配置才覆盖，没有配置 → 走原始逻辑
            const char *fake = [osv UTF8String];
            size_t len = strlen(fake) + 1;

            if (oldp && oldlenp && *oldlenp >= len) {
                memcpy(oldp, fake, len);
                *oldlenp = len;
            } else if (oldlenp) {
                *oldlenp = len;
            }
            NSLog(@"[hook] kern.osproductversion 修改为： %s", fake);
            return 0;
        }
    }
    
    // kern.osversion
    else if (strcmp(name, "kern.osversion") == 0) {
        getOrigSysctlString("kern.osversion");
        NSString *osv = config[@"osversion"];//20B101、21G93
        if (osv) {//有配置才覆盖，没有配置 → 走原始逻辑
            const char *fakeVersion = [osv UTF8String];
            size_t len = strlen(fakeVersion) + 1;
            if (oldp && oldlenp && *oldlenp >= len) {
                memcpy(oldp, fakeVersion, len);
                *oldlenp = len;
            } else if (oldlenp) {
                *oldlenp = len;
            }
            NSLog(@"[hook] kern.osversion 修改为： %s", fakeVersion);
            return 0;
        }
    }

    // 其他 key 或没配置的情况，直接走原始
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


// ---------- FYEDevice hardwareModel hook ----------
static NSString *(*orig_FYEDevice_hardwareModel)(id, SEL) = NULL;
static NSString *hook_FYEDevice_hardwareModel(id self, SEL _cmd) {
    // 调用原实现获取原始返回
    NSString *orig = orig_FYEDevice_hardwareModel(self, _cmd);

    // 获取配置中的 "dModel" 覆盖值
    NSDictionary *config = configDict();
    NSString *override = config[@"dModel"];

    // 如果配置了覆盖值，使用覆盖的值
    if (override) {
        NSLog(@"[HOOK] -[FYEDevice hardwareModel] original: %@ => overridden: %@", orig, override);
        return override;
    }

    // 如果没有配置覆盖值，返回原始值
    NSLog(@"[HOOK] -[FYEDevice hardwareModel] original: %@", orig);
    return orig;
}


// 声明原始的类方法
static NSString *(*orig_FYEDevice_getSystemBuildVersion)(id, SEL) = NULL;
static NSString *hook_FYEDevice_getSystemBuildVersion(id self, SEL _cmd) {
    // 调用原实现获取原始返回值
    NSString *orig = orig_FYEDevice_getSystemBuildVersion(self, _cmd);

    // 获取配置中的 "systemBuild" 覆盖值
    NSDictionary *config = configDict();
    NSString *override = config[@"systemBuild"];

    if (override) {
        // 如果配置了覆盖值，使用覆盖值
        NSLog(@"[HOOK] +[FYEDevice getSystemBuildVersion] original: %@ => overridden: %@", orig, override);
        return override;
    }

    // 如果没有配置覆盖值，打印原值并返回
    NSLog(@"[HOOK] +[FYEDevice getSystemBuildVersion] original: %@", orig);
    return orig;
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


        // UIDevice
        Class UIDeviceClass = objc_getClass("UIDevice");
        if (UIDeviceClass) {
            swizzle_instance_method(UIDeviceClass, @selector(identifierForVendor), (IMP)hook_UIDevice_identifierForVendor, (IMP *)&orig_UIDevice_identifierForVendor, "@@:");
            swizzle_instance_method(UIDeviceClass, @selector(systemVersion), (IMP)hook_UIDevice_systemVersion, (IMP *)&orig_UIDevice_systemVersion, "@@:");
            swizzle_instance_method(UIDeviceClass, @selector(model), (IMP)hook_UIDevice_model, (IMP *)&orig_UIDevice_model, "@@:");
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
        Class NSURLSessionClass = objc_getClass("NSURLSession");
        if (NSURLSessionClass) {
            swizzle_instance_method(NSURLSessionClass, @selector(dataTaskWithRequest:completionHandler:), (IMP)hook_NSURLSession_dataTaskWithRequest_completionHandler, (IMP *)&orig_NSURLSession_dataTaskWithRequest_completionHandler, "@@:@?"); // types: id,SEL,NSURLRequest*,block
        }

        // NSBundle
        Class NSBundleClass = objc_getClass("NSBundle");
        if (NSBundleClass) {
            swizzle_instance_method(NSBundleClass, @selector(infoDictionary), (IMP)hook_NSBundle_infoDictionary, (IMP *)&orig_NSBundle_infoDictionary, "@@:");
        }

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


        // 使用 fishhook 替换 FYEDevice 的 hardwareModel 方法
        Class FYEDeviceClass = objc_getClass("FYEDevice");
        if (FYEDeviceClass) {
            swizzle_instance_method(FYEDeviceClass, @selector(hardwareModel), (IMP)hook_FYEDevice_hardwareModel, (IMP *)&orig_FYEDevice_hardwareModel, "@@:");
            // Swizzle 类方法
            Method originalMethod = class_getClassMethod(FYEDeviceClass, @selector(getSystemBuildVersion));
            if (originalMethod) {
                orig_FYEDevice_getSystemBuildVersion = (void *)method_getImplementation(originalMethod);
                method_setImplementation(originalMethod, (IMP)hook_FYEDevice_getSystemBuildVersion);
                NSLog(@"[HOOK] Successfully hooked +[FYEDevice getSystemBuildVersion]");
            }
        }
        NSLog(@"[HOOK] hooks installed");
    }
}