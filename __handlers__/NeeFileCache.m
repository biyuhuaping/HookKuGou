@implementation NeeFileCache

- (id)objectForKeyedSubscript:(id)key {
    //@"appUdid"
    return [self objectForKey:key];
}

//-[NeeFileCache objectForKey:] listen.searchmodule.url.search_no_focus_word
- (NSData *)objectForKey:(id)key {
    NSString *filePath = [self fileNameForKey:key];
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    return data;
}

- (NSString *)fileNameForKey:(id)key {
    // 1️⃣ 复制 key（防止可变对象问题）
    NSString *fileKey = [key copy];

    NSString *basePath = nil;

    // 2️⃣ 判断是否存在 cacheUser 且 length > 0
    NSString *cacheUser = [self cacheUser];
    if (cacheUser && cacheUser.length > 0) {
        // 确保 cachePath 存在
        NSString *cachePath = [self checkCachePath];

        // basePath = cachePath + "cacheUser/"
        basePath = [cachePath stringByAppendingFormat:@"%@/", cacheUser];
    } else {
        // 没有 cacheUser，直接使用 cachePath
        basePath = [self checkCachePath];
    }

    // 3️⃣ 确保目录存在（如果不存在就创建）
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:basePath]) {
        [fm createDirectoryAtPath:basePath withIntermediateDirectories:YES attributes:nil error:nil];
    }

    // 4️⃣ 拼接最终文件路径
    NSString *filePath = [basePath stringByAppendingString:fileKey];
    return filePath;
}


- (NSString *)libCachePath {

    // 1️⃣ 获取 Library 目录（NSUserDomainMask）
    NSArray<NSString *> *paths =
        NSSearchPathForDirectoriesInDomains(
            NSLibraryDirectory,   // = 5
            NSUserDomainMask,     // = 1
            YES                   // expandTilde
        );

    // 2️⃣ 安全取第 0 个（Library 目录）
    NSString *libraryPath =
        [paths objectAtIndexKGSafe:0 class:[NSString class]];

    // 3️⃣ 拼接 "/Caches"
    NSString *cachePath =
        [libraryPath stringByAppendingFormat:@"/Caches"];

    // 4️⃣ touch 目录（确保存在）
    [self touch:cachePath];

    // 5️⃣ 返回缓存路径
    return cachePath;
}

@end


// NeeFileCache fileNameForKey: 
//key: listen.searchmodule.url.search_no_focus_word
//value: /var/mobile/Containers/Data/Application/27E88CE9-27A6-43C5-80BE-247002FD77AB/Library/Caches/listenHomepage/listen.searchmodule.url.search_no_focus_word

// key: MixIds_0_1_1_0
// value: /var/mobile/Containers/Data/Application/27E88CE9-27A6-43C5-80BE-247002FD77AB/Library/Caches/DailyRec/20449/MixIds_0_1_1_0

// key: DR_0_1_1_0
// value: /var/mobile/Containers/Data/Application/27E88CE9-27A6-43C5-80BE-247002FD77AB/Library/Caches/DailyRec/20449/DR_0_1_1_0

// key: db88f861a4d2c303eaf1cefdefd89a04
// value: /var/mobile/Containers/Data/Application/27E88CE9-27A6-43C5-80BE-247002FD77AB/Library/Caches/AlbumShowInfo/db88f861a4d2c303eaf1cefdefd89a04