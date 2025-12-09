+ (NSString *)signFillUrlCustomParameterDictionary:(NSDictionary *)urlParams
                                        bodyString:(NSDictionary *)body
                                      isCdnRequest:(BOOL)isCdn
                                         signature:(NSString **)outSignature
                                             appid:(NSString *)appid
                                           saltKey:(NSString *)saltKey
                                         is256Sign:(BOOL)is256
{
    body      = [HippyI18nUtils copy:body];
    urlParams = [HippyI18nUtils copy:urlParams];
    appid     = [HippyI18nUtils copy:appid];
    saltKey   = [HippyI18nUtils copy:saltKey];

    NSMutableDictionary *dict = [NSMutableDictionary new];
    //公共参数
    NSDictionary *pub = [[KGNetworkTools class] urlPublicParameterDictionary:appid];

    // 如果 body 有 clienttime → 覆盖 publicParams 的 clienttime
    id ct = body[@"clienttime"];
    if (ct) {
        NSMutableDictionary *tmp = [pub mutableCopy];
        id ct2 = [body objectForKeyKGSafe:@"clienttime" class:[NSString class]];
        if (ct2) tmp[@"clienttime"] = ct2;
        pub = [tmp copy];
    }

    // 如果 body 有值，则合并到 dict
    if (body.count > 0) { 
        [dict addEntriesFromDictionary:body];
    }
    // 如果有 saltKey，将 appid: saltKey 加入 publicParams
    if (pub.count) {
        if (![StringTool isEmptyStr:saltKey]) {
            NSMutableDictionary *tmp = [NSMutableDictionary dictionaryWithDictionary:pub];
            tmp[@"appid"] = saltKey;
            pub = tmp;
        }
    }

    if (pub.count) [dict addEntriesFromDictionary:pub];

    // 排序
    NSArray *keys = [[dict allKeys] sortedArrayUsingComparator:...];

    NSMutableArray *arr1 = [NSMutableArray new];
    NSMutableArray *arr2 = [NSMutableArray new];

    // 遍历每个 key
    for (NSString *key in keys) {
        id value = [dict objectForKeyKGSafe:key class:[NSObject class]];

        NSString *str = nil;

        if ([value isKindOfClass:[NSString class]] ||
            [value isKindOfClass:[NSNumber class]]) {
            str = [[value copy] URLEncodedString];
        } else if ([value isKindOfClass:[NSDictionary class]] ||
                   [value isKindOfClass:[NSArray class]]) {
            str = [value JSONString2];
        } else {
            str = @"";
        }

        NSString *pair1 = [NSString stringWithFormat:@"%@=%@", key, str];
        NSString *pair2 = [NSString stringWithFormat:@"%@=%@", key, str];

        [arr1 addObjKGSafe:pair1];
        [arr2 addObjKGSafe:pair2];
    }

    NSString *join1 = [arr1 componentsJoinedByString:@"&"];
    NSString *join2 = [arr2 componentsJoinedByString:@""];

    // 获取 appKey
    NSString *appKey = saltKey.length ? saltKey : [[KGConfigEntity instance] appKey];

    NSString *sign = nil;

    if (isCdn) {
        // CDN 签名 = Data 方式
        NSMutableData *data = [NSMutableData data];

        if (appKey)  [data appendData:[appKey dataUsingEncoding:4]];
        if (join1)   [data appendData:[join1 dataUsingEncoding:4]];
        if (saltKey) {
            NSData *d = [saltKey dataUsingEncoding:4];
            if (d.length > 0x100) d = [d subdataWithRange:NSMakeRange(0, 0x100)];
            [data appendData:d];
        }
        if (appKey)  [data appendData:[appKey dataUsingEncoding:4]];

        // 256 或 普通 md5
        sign = [data md5String]; // 汇编里就是 md5 or md5String
    }
    else {
        // 普通签名 = String 方式
        NSMutableString *s = [NSMutableString string];
        if (appKey)  [s appendString:appKey];
        if (join1)   [s appendString:join1];
        if (saltKey) [s appendString:saltKey];
        if (appKey)  [s appendString:appKey];

        sign = [s md5];
    }

    if (outSignature) *outSignature = sign;

    return [NSString stringWithFormat:@"?%@&signature=%@", join1, sign];
}
