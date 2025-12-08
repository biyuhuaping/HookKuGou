#import <Foundation/Foundation.h>
#import "NeeFileCache.h"
#import "NeeSandbox.h"
#import "TrackerLiteContext.h"

@implementation AlbumShowBLL

+ (void)saveAlbumShowInfoCache:(id)info {
    // === 对应反汇编：MOV X0, X2 ; BL __HippyI18nUtils_copy__0 -> copy 参数到 X19
    id copied = [info copy];
    if (!copied) {
        // loc_1047B83B4 跳转点：参数为 nil，直接返回
        return;
    }

    // 对应反汇编：BL j__objc_msgSend$count -> 调用 count 检查非空集合
    // 如果不是集合也可根据实际替换，反汇编表明调用了 count 并检查 CBZ
    if ([copied respondsToSelector:@selector(count)]) {
        if ([copied count] == 0) {
            return;
        }
    }

    // 对应反汇编：alloc + BL __KGListenMoudleLifecyleMounter_initKGAppMoudleWithConfiguration___0
    // 这里反汇编先 alloc，再调用名为 initKGAppMoudleWithConfiguration: 的 init 方法（参数未知，传 nil）
    NeeFileCache *cache = [[NeeFileCache alloc] initKGAppMoudleWithConfiguration:nil];

    // 对应反汇编：取得 NSString 类并构造缓存路径（通过 TrackerLiteContext / NeeSandbox）
    // +[TrackerLiteContext setBaseContext:] 传入 NeeSandbox 类，返回一个 context（反汇编把返回值保存在 X22）
    id ctx = [TrackerLiteContext setBaseContext:[NeeSandbox class]];
    // 接着调用 [ctx libCachePath] 得到 base cache path（反汇编 j__objc_msgSend$libCachePath）
    NSString *basePath = nil;
    if (ctx && [ctx respondsToSelector:@selector(libCachePath)]) {
        basePath = [ctx libCachePath];
    }

    // 反汇编把 basePath 和常量 "AlbumShowInfo" 用 "%@/%@/" 组合成 cachePath
    NSString *cachePath = nil;
    if (basePath) {
        cachePath = [NSString stringWithFormat:@"%@/%@/", basePath, @"AlbumShowInfo"];
    } else {
        // 保险起见：如果没有 basePath，则仍用默认相对路径
        cachePath = [NSString stringWithFormat:@"%@/%@/", @"", @"AlbumShowInfo"];
    }

    // 对应反汇编：调用 [cache setCachePath:cachePath]
    if (cache && cachePath) {
        [cache setCachePath:cachePath];
    }

    // 对应反汇编：计算 key，反汇编流程如下：
    //   X22 <- cfstr_SidebarAlbumsh ("sidebar_albumshow_info")
    //   X23 <- [X22 MD5] ; X24 <- [X23 length]
    //   if (X24 == 0) 跳过
    //   else X23 <- [X22 MD5]; X22 <- [X23 lowercaseString]
    // 因此按反汇编我们两次调用 MD5（反编译器如此生成），最后得到一个小写的 md5 作为 key。
    NSString *key = nil;
    @autoreleasepool {
        NSString *const rawKey = @"sidebar_albumshow_info";
        NSString *tmp = nil;
        if ([rawKey respondsToSelector:@selector(MD5)]) {
            tmp = [rawKey MD5]; // 第一次 MD5（反汇编有此调用）
        }
        if (tmp && [tmp length] > 0) {
            // 反汇编再次对原始字符串调用 MD5，然后 lowercaseString
            NSString *tmp2 = [rawKey MD5];
            if (tmp2) {
                key = [tmp2 lowercaseString];
            }
        }
    }

    // 对应反汇编：使用 NSKeyedArchiver archivedDataWithRootObject: 序列化 copied（X19）
    NSData *archived = [NSKeyedArchiver archivedDataWithRootObject:copied];
    if (archived) {
        // 对应反汇编：- [NeeFileCache setObject:forKeyedSubscript:] 调用（cache[X22] = archived）
        if (key) {
            // 用 keyed subscript 接口写入
            cache[key] = archived;
        } else {
            // 如果 key 为 nil（按反汇编 key 可能为 nil），可以选择用默认 key 或跳过写入
            // 此处按反汇编：如果没有 key 则不写（反汇编分支里 X24==0 会跳过 setObject）
        }
    }

    // ARC 下不显式释放，反汇编里显示了一系列 objc_release（编译器插入）
    return;
}

@end
