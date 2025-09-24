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
    NSString *modelStr = config[@"model"];
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
    NSDictionary *config = configDict();
    NSNumber *dx = config[@"dx"];
    NSNumber *dy = config[@"dy"];
    if ([dx isKindOfClass:[NSNumber class]] && [dy isKindOfClass:[NSNumber class]]) {
        CGFloat w = dx.floatValue;
        CGFloat h = dy.floatValue;
        NSLog(@"[Hook] override bounds: %.0f x %.0f", w, h);
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
    NSDictionary *config = configDict();
    NSNumber *ndx = config[@"ndx"];
    NSNumber *ndy = config[@"ndy"];
    if ([ndx isKindOfClass:[NSNumber class]] && [ndy isKindOfClass:[NSNumber class]]) {
        CGFloat w = ndx.floatValue;
        CGFloat h = ndy.floatValue;
        NSLog(@"[Hook] override nativeBounds: %.0f x %.0f", w, h);
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
        NSLog(@"[HOOK] override DTPlatformVersion: %@", fakeOS);
        mutableDict[@"DTPlatformVersion"] = fakeOS;
    }
    return [mutableDict copy];
}

// ---------- sysctlbyname via fishhook ----------
static int (*orig_sysctlbyname)(const char *, void *, size_t *, const void *, size_t) = NULL;
static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    NSDictionary *config = configDict();
    if (strcmp(name, "hw.machine") == 0) {
        if (oldp) {
            const char *machine1 = [(config[@"model"] ?: @"iPhone14,6") UTF8String];
            // 注意安全：确保 oldlenp 足够
            size_t need = strlen(machine1) + 1;
            if (oldlenp && *oldlenp >= need) {
                memcpy(oldp, machine1, need);
                if (oldlenp) *oldlenp = need;
            } else if (oldlenp) {
                // 报告长度，但不写
                *oldlenp = need;
            }
            NSLog(@"sysctlbyname override hw.machine: %s", machine1);
            return 0;
        }
    }
    // 其他 key 保持原样
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
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
        struct rebinding rb;
        rb.name = "sysctlbyname";
        rb.replacement = (void *)hook_sysctlbyname;
        rb.replaced = (void *)&orig_sysctlbyname;
        rebind_symbols(&rb, 1);

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

        NSLog(@"[HOOK] hooks installed");
    }
}
