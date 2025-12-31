//+[KGAPMCenter generateErrorLevelBSInfoAPMTool:andError:andNodeIndex:andBSID:]

// 生成错误信息
+ (NSDictionary *)generateErrorLevelBSInfoAPMTool:(NSInteger)tool andError:(NSError *)error andNodeIndex:(NSInteger)nodeIndex andBSID:(NSInteger)bsid {
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithCapacity:10];
    dict[@"te"] = [NSString stringWithFormat:@"E%@", @(tool)];
    dict[@"fs"] = @(error.code);
    if ([error.domain isEqualToString:kKGErrorDomainTypeNetworkComponent]) {
        if (error.code == 0x9C41) {
        } else if (error.code == 0x9C42) {
        }
    }
    if (error.code == 0x2712) {
        NSDictionary *ui = error.userInfo;
        NSString *httpCode = [ui kg_stringForKey:@"HTTP_RESPONSE_CODE_KEY"];
        dict[@"fs"] = [NSString stringWithFormat:@"%d-%d", (int)error.code, httpCode.intValue];
    }
    NSDictionary *oldInfo = [error.userInfo dictionaryForKeyKGSafe:@"KugouErrorOldUserInfo"];
    NSError *underErr = [oldInfo objectForKey:NSUnderlyingErrorKey class:[NSError class]];
    if (underErr) dict[@"fs"] = [NSString stringWithFormat:@"%d%d", (int)error.code, (int)underErr.code];
    dict[@"position"] = @(nodeIndex);
    if ([self shouldAddCompeltedAPMType:bsid] && [error respondsToSelector:@selector(kgCompeltedErrorDetail)]) dict[@"para2"] = [error kgCompeltedErrorDetail];
    if ([error isKindOfClass:[HttpError class]]) {
        HttpError *he = (HttpError *)error;
        dict[@"offline4"] = @(he.pageID);
        if (he.sessionID.length > 0) dict[@"offline5"] = he.sessionID;
    }
    NSString *appVer = [KGDataChannel sharedInstance].appVersion;
    NSString *md5 = [@"Kugou2014" md5];
    dict[@"Kgsign"] = [NSString stringWithFormat:@"%ld%d%@%@", (long)bsid, 0, appVer, md5];
    return dict;
}

- (id)processAPMData:(id)data andHistoryAMPData:(id)history {
    id bsid = nil;
    if ([history bsID] && [[history bsID] length] > 0) {
        NSArray *arr = [[history bsID] componentsSeparatedByString:@"-"];
        if (arr.count > 0) {
            bsid = [arr stringAtIndexKGSafe:0];
        }
    }
    
    NSString *appVer = [self appVersion];
    NSString *md5 = [@"Kugou2014" md5];
    NSString *kgsign = [NSString stringWithFormat:@"%@%d%@%@", bsid, 1, appVer, md5];
    
    NSMutableDictionary *ret = nil;
    if (data) {
        if (![[data allKeys] containsObject:@"Kgsign"]) {
            [data setValue:kgsign forKey:@"Kgsign"];
        }
        ret = [data retain];
    } else {
        NSDictionary *dic = @{@"Kgsign": kgsign};
        ret = [NSMutableDictionary dictionaryWithDictionary:dic];
    }
    
    return ret;
}

