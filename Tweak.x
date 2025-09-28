#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>   // 提供CTL_HW, HW_NCPU等常量
#import <sys/time.h>     // 提供timeval结构
#import <string.h>       // 提供strncpy等函数
#import <AdSupport/AdSupport.h>  // 用于ASIdentifierManager
#import <sys/utsname.h>     // 用于struct utsname结构体
#include <sys/stat.h>


//读取JSON配置文件
static NSDictionary *configDict() {
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

%hook UIDevice
//idfv
- (NSUUID *)identifierForVendor {
    NSUUID *orig = %orig;
    NSDictionary *config = configDict();
    NSString *customIDFV = config[@"idfv"];
    if (customIDFV.length){
        orig = [[NSUUID alloc] initWithUUIDString:customIDFV];
    }
    NSLog(@"[HOOK]-idfv: %@", orig.UUIDString);
    return orig;
}
// 修改系统版本 17.6.1
- (NSString *)systemVersion {
    NSDictionary *config = configDict();
    NSString *sVersion = config[@"osv"];
    NSLog(@"[HOOK]-systemVersion: %@", sVersion);
    return sVersion ?: %orig;
}
// 伪造 model, @"iPhone15,2"; 伪造成 @"iPhone10,2"
- (NSString *)model {
    NSDictionary *config = configDict();
    NSString *modelStr = config[@"model"];
    NSLog(@"[HOOK]-model: %@", modelStr);
    return modelStr ?: %orig;
}
%end

%hook ASIdentifierManager
//idfa
- (NSUUID *)advertisingIdentifier {
    NSUUID *orig = %orig;
    NSDictionary *config = configDict();
    NSString *customIDFA = config[@"idfa"];
    if (customIDFA.length){
        orig = [[NSUUID alloc] initWithUUIDString:customIDFA];
    }
    NSLog(@"[HOOK]-idfa: %@", orig);
    return orig;
}
%end


%hook UIScreen
// 修改分辨率
- (CGRect)bounds {
    CGRect value = %orig;
    NSDictionary *config = configDict();
    
    NSNumber *dx = config[@"dx"];
    NSNumber *dy = config[@"dy"];
    
    if ([dx isKindOfClass:[NSNumber class]] && [dy isKindOfClass:[NSNumber class]]) {
        CGFloat w = dx.floatValue;
        CGFloat h = dy.floatValue;
        NSLog(@"[Hook] 配置伪造 bounds: %.0f x %.0f", w, h);
        return CGRectMake(0, 0, w, h);
    }
    NSLog(@"[Hook] 使用原始 bounds: %@", NSStringFromCGRect(value));
    return value;
}

// 修改屏幕缩放比例为 3x
- (CGFloat)scale {
    CGFloat value = %orig;
   NSLog(@"[Hook] 原始屏幕缩放比例: %f", value);
    NSDictionary *config = configDict();
    NSNumber *configScale = config[@"scale"];
    if ([configScale isKindOfClass:[NSNumber class]]) {
        NSLog(@"[Hook] 屏幕缩放比例: %f", configScale.floatValue);
        value = configScale.floatValue;
    }
    return value;
}

// 修改物理分辨率
- (CGRect)nativeBounds {
    CGRect value = %orig;
    NSDictionary *config = configDict();
    
    NSNumber *ndx = config[@"ndx"];
    NSNumber *ndy = config[@"ndy"];
    
    if ([ndx isKindOfClass:[NSNumber class]] && [ndy isKindOfClass:[NSNumber class]]) {
        CGFloat w = ndx.floatValue;
        CGFloat h = ndy.floatValue;
       	NSLog(@"[Hook] 配置伪造 nativeBounds: %.0f x %.0f", w, h);
        return CGRectMake(0, 0, w, h);
    }
    NSLog(@"[Hook] 使用原始 nativeBounds: %@", NSStringFromCGRect(value));
    return value;
}

%end


%hook NSURLRequest
- (NSDictionary *)allHTTPHeaderFields {
    NSMutableDictionary *headers = [%orig mutableCopy];
    // NSDictionary *config = configDict();
    NSLog(@"[Hook] User-Agent原始数据：%@", headers);
    return headers;
}
%end


// Hook sysctlbyname 函数，通过名称获取系统信息
%hookf(int, sysctlbyname, const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = %orig;  // 先调用原始函数
    // 读取配置文件
    NSDictionary *config = configDict();
    // 伪造设备硬件型号
    if (strcmp(name, "hw.machine") == 0) {
        if (oldp) {
            const char *machine1 = [(config[@"model"] ?: @"iPhone14,6") UTF8String];
            strcpy((char *)oldp, machine1);
            NSLog(@"sysctlbyname 修改设备硬件型号: %s", machine1);
        }
        return ret;
    }

    // 伪造设备屏幕分辨率
    // if (strcmp(name, "hw.resolution") == 0) {
    //     if (oldp) {
    //         // 从配置文件读取物理分辨率
    //         NSDictionary *config = configDict();
    //         int ndx = [config[@"ndx"] intValue] ?: 1170;  // 默认1170
    //         int ndy = [config[@"ndy"] intValue] ?: 2532;  // 默认2532
    //         NSString *res = [NSString stringWithFormat:@"%dx%d", ndx, ndy];
    //         strncpy((char *)oldp, res.UTF8String, res.length);
    //         NSLog(@"[Hook]sysctlbyname 修改设备分辨率: %@", res);
    //     }
    //     return ret;
    // }

    // 伪造iOS版本
    // if (strcmp(name, "kern.osversion") == 0) {
    //    if (oldp) {
    //        const char *buildVersion = "21E230"; // 伪造iOS 17.4的构建版本
    //        strcpy((char *)oldp, buildVersion);
    //        NSLog(@"sysctlbyname 修改iOS版本: %s", buildVersion);
    //     }
    //     if (oldlenp) {
    //        *oldlenp = strlen("21E230");
    //     }
    //     return ret;
    // }
    return ret;
}

/*/修改 machine的系统版本号
static int (*orig_sysctlbyname)(const char *, void *, size_t *, const void *, size_t);
static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, const void *newp, size_t newlen) {
    NSDictionary *config = configDict();
    if (strcmp(name, "kern.osproductversion") == 0) {
       NSDictionary *config = configDict();
        NSString *osv = config[@"osv"];  // "17.6.1"
        if (osv && [osv isKindOfClass:[NSString class]]) {
            const char *fake = [osv UTF8String];
            size_t len = strlen(fake) + 1;

            if (oldp && oldlenp && *oldlenp >= len) {
                memcpy(oldp, fake, len);
                *oldlenp = len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = len;
                return 0;
            }
        }
    }else if (strcmp(name, "kern.osversion") == 0) {
        NSString *osv = config[@"osversion"];//21G93
        if ([osv isKindOfClass:[NSString class]]) {
            const char *fakeVersion = [osv UTF8String];
            size_t len = strlen(fakeVersion) + 1;
            if (oldp && oldlenp && *oldlenp >= len) {
                memcpy(oldp, fakeVersion, len);
                *oldlenp = len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = len;
                return 0;
            }
        }
    } else if (strcmp(name, "hw.machine") == 0) {
        NSString *model = config[@"model"];//iPhone9,1
        if ([model isKindOfClass:[NSString class]]) {
            const char *fakeMachine = [model UTF8String];
            size_t len = strlen(fakeMachine) + 1;
            if (oldp && oldlenp && *oldlenp >= len) {
                memcpy(oldp, fakeMachine, len);
                *oldlenp = len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = len;
                return 0;
            }
        }
    } else if (strcmp(name, "hw.model") == 0) {
        NSString *str = config[@"model"];//D84AP
        if ([str isKindOfClass:[NSString class]]) {
            const char *fakeMachine = [str UTF8String];
            size_t len = strlen(fakeMachine) + 1;
            if (oldp && oldlenp && *oldlenp >= len) {
                memcpy(oldp, fakeMachine, len);
                *oldlenp = len;
                return 0;
            } else if (oldlenp) {
                *oldlenp = len;
                return 0;
            }
        }
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ✅ fishhook 替换符号
__attribute__((constructor))
static void hook_sysctlbyname_func() {
    struct rebinding reb = {
        "sysctlbyname",
        (void *)my_sysctlbyname,
        (void **)&orig_sysctlbyname
    };
    rebind_symbols(&reb, 1);
}
*/


%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler{
    NSString *url = request.URL.absoluteString;
    NSLog(@"[hook]RequestURL: %@", url);

    __block NSString *requestBody = nil;
    if (request.HTTPBody) {
        requestBody = [[NSString alloc] initWithData:request.HTTPBody encoding:NSUTF8StringEncoding];
        NSLog(@"[hook] Request Body: %@", requestBody);
    }

    void (^customCompletion)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSString *responseBody = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSLog(@"[hook] 请求：%@\n入参：%@\n出参：%@", url, requestBody, responseBody);
        completionHandler(data, response, error);
    };
    return %orig(request, customCompletion);
}
%end


%hook NSBundle
- (NSDictionary *)infoDictionary {
    NSDictionary *originalDict = %orig;
    NSMutableDictionary *mutableDict = [originalDict mutableCopy];

    NSDictionary *config = configDict();
    NSString *fakeOS = config[@"osv"];
    if (fakeOS && mutableDict[@"DTPlatformVersion"]) {
        NSLog(@"[HOOK] 替换 Info.plist 中的 DTPlatformVersion: %@", fakeOS);
        mutableDict[@"DTPlatformVersion"] = fakeOS;
    }
    return [mutableDict copy];
}
%end


%hook FYEDevice
- (id)hardwareModel {
    // 调用原实现获取原始返回
    id orig = %orig;
    NSDictionary *config = configDict();
    NSString *override = config[@"dModel"];//iPhone13,4
    if (override) {//有配置才覆盖，没有配置 → 走原始逻辑
        orig = override;
    }
    NSLog(@"[HOOK] -[FYEDevice hardwareModel] %@ => %@", orig, %orig);
    // 如果想要篡改返回，取消下面注释并改成目标值
    // NSString *fake = @"iPhone12,1";
    // return fake;
    return orig;
}
%end