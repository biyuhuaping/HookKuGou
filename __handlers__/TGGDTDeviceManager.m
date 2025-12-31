
@implementation TGGDTDeviceManager
+ (TGGDTDeviceManager *)defaultManager {
    static TGGDTDeviceManager *manager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        manager = [[self alloc] init];
    });
    return manager;
}


- (void)collectDeviceInfo:(NSMutableDictionary *)dict
{
    // 防御：必须是可变字典
    if (![dict isKindOfClass:[NSMutableDictionary class]]) {
        return;
    }

    /// 1️⃣ EBID（可能是业务侧设备 ID）
    NSString *ebid = [[TGGDTSettingManager defaultManager] ebid];
    if (ebid.length > 0) {
        [dict gdt_safeSetObject:ebid forKey:@"ebid"];
    }

    /// 2️⃣ 硬件型号 hw.machine
    [dict gdt_safeSetObject:self->_hwMachine forKey:@"md"];
    [self synSafeSetObject:self->_hwMachine forKey:@20 withContainer:[self fetchSettinglist]];

    /// 3️⃣ OS 名称（iOS）
    [dict gdt_safeSetObject:self->_os forKey:@"os"];
    [self synSafeSetObject:self->_os forKey:@24 withContainer:[self fetchSettinglist]];

    /// 4️⃣ OS 版本
    [dict gdt_safeSetObject:self->_osver forKey:@"osv"];
    [self synSafeSetObject:self->_osver forKey:@10 withContainer:[self fetchSettinglist]];

    /// 5️⃣ IDFV
    [dict gdt_safeSetObject:self->_idfv forKey:@"iv"];
    [self synSafeSetObject:self->_idfv orKey:@9 withContainer:[self fetchSettinglist]];

    /// 6️⃣ 判断是否已有安全 FAID（⚠️风控分支）
    BOOL hasSecureFAID = [[self gathering] isSecureFAIDFromCache];

    if (!hasSecureFAID) {
        /// m12（高度可疑的设备指纹）
        [dict gdt_safeSetObject:self->_m12 forKey:@"m12"];
        [self synSafeSetObject:self->_m12 forKey:@7 withContainer:[self fetchSettinglist]];

        /// did（设备唯一 ID）
        [dict gdt_safeSetObject:self->_muid forKey:@"did"];
        [self synSafeSetObject:self->_muid forKey:@8 withContainer:[self fetchSettinglist]];
    }

    /// 7️⃣ TAID / Ticket
    [dict gdt_safeSetObject:self->_taid_ticket forKey:@"td"];

    /// 8️⃣ QIMEI36（腾讯系设备终极指纹）
    id hostInfo = [GDTTangramDeviceManager getHostDeviceInfo];

    NSString *qimei36 = [hostInfo qimei36];
    [dict gdt_safeSetObject:qimei36 forKey:@"qimei36"];
}

// 获取当前蜂窝网络制式（2G / 3G / 4G / 5G）
- (NSString *)currentRadioAccessTechnology {
    // CTTelephonyNetworkInfo
    CTTelephonyNetworkInfo *telephony = [[CTTelephonyNetworkInfo alloc] initKGAppMoudleWithConfiguration:nil];

    // 读取系统版本
    UIDevice *device = [UIDevice currentDevice];
    NSString *systemVersion = [device systemVersion];
    double version = [systemVersion doubleValue];

    NSString *radioTech = nil;

    /// =========================
    /// iOS 12+ & API 可用
    /// =========================
    if (version >= 12.0 && [telephony canPerformAction:@selector(serviceCurrentRadioAccessTechnology) withSender:nil]){
        // iOS 12+：返回 NSDictionary<NSString*, NSString*>
        NSDictionary *techDict = [telephony serviceCurrentRadioAccessTechnology];
        if (techDict.count > 0) {
            // 取第一个 SIM 的 radio tech
            NSString *key = techDict.allKeys.firstObject;
            radioTech = techDict[key];
        }
    }

    /// =========================
    /// 兜底逻辑（老 API）
    /// =========================
    if (radioTech.length == 0 && [telephony canPerformAction:@selector(currentRadioAccessTechnology) withSender:nil]) {
        // iOS 11 及以下
        radioTech = [telephony currentRadioAccessTechnology];
    }
    return radioTech;
}

- (void)updateData {
    // 当前时间
    int64_t currentTime = [TGGDTTimeUtil currentTime];

    // 初始化容器
    [self initDeviceMap];

    // gathering
    self.gathering = [TuringGatheringXXQ sharedService];

    // CTNetworkInfo
    id ctInfo = [GDTTangramDeviceManager getCTNetWorkInfo];
    BOOL useNewLogic = [[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"is_use_networkinfo_by_app"];

    if (ctInfo && [ctInfo isKindOfClass:[CTTelephonyNetworkInfo class]] && useNewLogic) {
        [self.gathering setIsUseNewLogicGetNetworkInfo:YES];
    }

    [self.gathering setCTNetWorkInfo:ctInfo];

    // bundleId
    if (![[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeBundleId"]) {
        self.an = [self.gathering getAppBundleIdentifierWithError:nil];
        [self synSafeSetObject:self.an forKey:@2 withContainer:[self fetchADlist]];
    }

    // appVersion
    if (![[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeAppVersion"]) {
        self.appVersion = [self.gathering getAppVersionStringWithError:nil];
        [self synSafeSetObject:self.appVersion forKey:@3 withContainer:[self fetchADlist]];
    }

    // 硬件 / IDFA
    [self updateHardwareInfo];
    [self updateIDFAInfo];

    // machine / device
    if (![[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeMachine"]) {
        self.hwMachine = [self.gathering getMachineWithError:nil];
        self.device = [self getMappingMachineName];
        [self synSafeSetObject:self.hwMachine forKey:@20 withContainer:[self fetchADlist]];
    }

    // idfv（优先使用 hostDeviceInfo）
    GDTTangramHostDeviceInfo *hostInfo = [GDTTangramDeviceManager getHostDeviceInfo];
    NSString *idfv = [hostInfo idfv];

    if (idfv.length > 0) {
        self.idfv = idfv;
        [self synSafeSetObject:self.idfv forKey:@9 withContainer:[self fetchADlist]];
    } else if (![[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeIdfv"]) {
        self.idfv = [self.gathering getIDFVWithError:nil];
        [self synSafeSetObject:self.idfv forKey:@9 withContainer:[self fetchADlist]];
    }

    // 经纬度
    if ([hostInfo lat] != 0) {
        self.lat = [hostInfo lat];
        NSString *latStr = @([hostInfo lat]).stringValue;
        [self synSafeSetObject:latStr forKey:@29 withContainer:[self fetchADlist]];
    }

    if ([hostInfo lng] != 0) {
        self.lng = [hostInfo lng];
        NSString *lngStr = @([hostInfo lng]).stringValue;
        [self synSafeSetObject:lngStr forKey:@30 withContainer:[self fetchADlist]];
    }

    // OS version
    if (![[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeOSversion"]) {
        self.osver = [self.gathering getSystemVersionStringWithError:nil];
        [self synSafeSetObject:self.osver forKey:@10 withContainer:[self fetchADlist]];
    }

    // Language
    if (![[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeLanguage"]) {
        self.languge = [self.gathering getPreferenceLanguageWithError:nil];
        [self synSafeSetObject:self.languge forKey:@11 withContainer:[self fetchADlist]];
    }

    // BootTime
    if (![[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeBootTime"]) {
        self.bootTime = [self.gathering getSystemBootTimestampWithError:nil];
        [self synSafeSetObject:self.bootTime forKey:@12 withContainer:[self fetchADlist]];
    }

    // SystemUpdateTime
    if (![[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeSysUpdateTime"]) {
        self.sysUpdateTime = [self.gathering getSystemUpdateTimeWithError:nil];
        [self synSafeSetObject:self.sysUpdateTime forKey:@13 withContainer:[self fetchADlist]];
    }

    // Country
    if (![[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeCountry"]) {
        self.countryC = [self.gathering getPreferenceCountryWithError:nil];
        [self synSafeSetObject:self.countryC forKey:@14 withContainer:[self fetchADlist]];
    }

    // DeviceName MD5
    if (![[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeDeviceName"]) {
        self.currentDeviceName = [self.gathering getDeviceNameMD5WithError:nil];
        [self synSafeSetObject:self.currentDeviceName forKey:@15 withContainer:[self fetchADlist]];
    }

    // Timezone
    if (![[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeTimezone"]) {
        self.timezone = [self.gathering getPreferenceTimeZoneWithError:nil];
        [self synSafeSetObject:self.timezone forKey:@16 withContainer:[self fetchADlist]];
    }

    // Model
    if (![[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeModel"]) {

        self.model =
            [self.gathering getModelWithError:nil];

        [self synSafeSetObject:self.model
                        forKey:@21
                 withContainer:[self fetchADlist]];
    }

    // Carrier
    if (![[TGGDTSettingManager defaultManager]
            appBoolObjectForKey:@"closeCarrier"]) {

        NSInteger carrier =
            [self.gathering getCarrierCodeWithError:nil];

        [self synSafeSetObject:@(carrier).stringValue
                        forKey:@22
                 withContainer:[self fetchADlist]];
    }

    // mntId
    if (![[TGGDTSettingManager defaultManager]
            appBoolObjectForKey:@"closeMntid"]) {

        self.mntId =
            [self.gathering getTNMIDWithError:nil];

        [self synSafeSetObject:self.mntId
                        forKey:@34
                 withContainer:[self fetchADlist]];
    }

    // deviceInitTime
    if (![[TGGDTSettingManager defaultManager]
            appBoolObjectForKey:@"closeDeviceInitTime"]) {

        self.deviceInitTime =
            [self.gathering getDeviceInitTimeWithError:nil];

        [self synSafeSetObject:self.deviceInitTime
                        forKey:@35
                 withContainer:[self fetchADlist]];
    }
}

- (void)updateIDFAInfo{
    // 先从 Host 设备信息中取 IDFA
    GDTTangramHostDeviceInfo *hostInfo = [GDTTangramDeviceManager getHostDeviceInfo];
    NSString *idfa = [hostInfo idfa];

    // =========================
    // ① Host IDFA 存在的情况
    // =========================
    if (idfa.length > 0) {
        // IDFA -> NSData
        NSData *idfaData = [idfa dataUsingEncoding:NSUTF8StringEncoding];

        // sub_1005D6F90(): 生成加密 key / salt（内部实现未知）
        id cryptoKey = (id)sub_1005D6F90();

        // 对 IDFA 数据进行加密，返回 NSData
        NSData *encryptedData = (NSData *)sub_1005D6E08((int)idfaData, cryptoKey);

        // Base64 编码后的 Secure FAID
        self->_m12 = [encryptedData base64EncodedStringWithOptions:0];

        // IDFA 的 MD5
        self->_muid = [TGGDTMD5Util md5HexDigest:idfa];

        // 原始 IDFA
        self->_m5 = idfa;

        // 记录事件：Host IDFA 命中
        [TGGDTLogger recordEventId:30609];

        // 写入 ADlist
        [[self fetchADlist] setObject:self->_m12 forKey:@7];
        [[self fetchADlist] setObject:self->_muid forKey:@8];

        // Debug / SDK 日志
        if ([GDTSDKPrivateConfig showDebugLog]) {
            NSString *log = [NSString stringWithFormat:@"hostIdfa _m12 = %@ _muid = %@ _m5 = %@",self->_m12, self->_muid, self->_m5];

            if ([GDTSDKPrivateConfig showNSLog]) {
                NSLog(@"%@", log);
            }

            [TGGDTLogger reportSDKGDTlog:log];
            [TGGDTLogger outputToAppDeveloperLevel:1 log:log];
        }
    }

    // =========================
    // ② Host IDFA 不存在
    // =========================
    else {
        // 是否关闭 IDFA
        BOOL closeIdfa = [[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"closeIdfa"];
        if (!closeIdfa) {
            // 读取历史缓存 IDFA
            NSString *cachedIdfa = [[NSUserDefaults standardUserDefaults] stringForKey:@"cache_adid"];
            if (cachedIdfa.length > 0) {
                // 写入 gathering
                [[self gathering] setOriginalFAID:cachedIdfa];

                // 清除缓存
                [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"cache_adid"];
            }

            // 是否允许 FAID 缓存
            BOOL enableCache =
            [[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"enableIdfaCache"];
            [[self gathering] setFAIDCacheEnable:enableCache];

            // 从 gathering 获取 IDFA
            self->_m5   = [[self gathering] getIDFAWithError:nil];
            self->_m12  = [[self gathering] getSecureFAIDWithError:nil];
            self->_muid = [[self gathering] getMD5FAIDWithError:nil];

            // 记录是否成功获取 Secure FAID
            [TGGDTLogger recordEventId:(self->_m12.length ? 30606 : 30605)];

            // 判断 Secure FAID 是否来自缓存
            if (self->_m12.length) {
                BOOL fromCache = [[self gathering] isSecureFAIDFromCache];
                [TGGDTLogger recordEventId:(fromCache ? 30607 : 30608)];
            }

            // 非缓存来源，写入 ADlist
            if (![[self gathering] isSecureFAIDFromCache]) {
                [[self fetchADlist] setObject:self->_m12 forKey:@7];
                [[self fetchADlist] setObject:self->_muid forKey:@8];
            }

            // Debug / SDK 日志
            if ([GDTSDKPrivateConfig showDebugLog]) {
                NSString *log = [NSString stringWithFormat:
                    @"gathering _m12 = %@ _muid = %@ _m5 = %@",
                    self->_m12, self->_muid, self->_m5
                ];

                if ([GDTSDKPrivateConfig showNSLog]) {
                    NSLog(@"%@", log);
                }

                [TGGDTLogger reportSDKGDTlog:log];
                [TGGDTLogger outputToAppDeveloperLevel:1 log:log];
            }
        }
    }

    // =========================
    // ③ 是否清理 FAID 缓存
    // =========================
    BOOL removeCache = [[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"removeIdfaCache"];
    if (removeCache) {
        [[self gathering] removeFAIDCache];
    }
}

// ARC 版本还原
// -[TGGDTDeviceManager setOriginalFAID:]
// 作用：从外部（通常是缓存）设置原始 FAID，并标记为“来自缓存”
- (void)setOriginalFAID:(id)faid{
    // 对传入的 FAID 做一次 copy，避免外部可变对象影响内部状态
    id copiedFAID = [faid copy];

    // 如果 FAID 不为空（合法）
    if (![self isFaidNull:copiedFAID]) {

        // 统一转成大写（IDFA/FAID 规范化处理）
        NSString *upperFAID = [copiedFAID uppercaseString];

        // 设置到内部 FAID 字段
        [self setFaid:upperFAID];

        // FAID 设置后的统一处理逻辑
        // （通常包括派生 secureFAID / md5FAID / 同步状态等）
        [self handleFAID];

        // 标记该 FAID 来源于缓存
        [self setIsFaidFromCache:YES];
    }
    // ARC 下显式 release 对应 retain/copy
    [copiedFAID release];
}

// ARC 版还原
// -[TGGDTDeviceManager handleFAID]
// 作用：基于 faid 生成 secureFaid（加密 + base64）和 md5Faid，并在允许时写入本地缓存
- (void)handleFAID{
    NSString *faid = [self faid];
    if ([faid length]) {
        NSData *data = [faid dataUsingEncoding:NSUTF8StringEncoding];
        id key = sub_1005D6F90(); // 获取加密 key / context（具体算法在该函数内）
        id encryptedData = sub_1005D6E08((int)data, key); // 对 FAID 做加密处理
        NSString *secureFaid = [encryptedData base64EncodedStringWithOptions:16];
        [self setSecureFaid:secureFaid];
        NSString *md5Faid = [TGGDTMD5Util md5HexDigest:faid];
        [self setMd5Faid:md5Faid];
        if ([self enableFaidCache]) {
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            [ud setObject:[self secureFaid] forKey:@"secure_faid"];
            NSUserDefaults *ud2 = [NSUserDefaults standardUserDefaults];
            [ud2 setObject:[self md5Faid] forKey:@"md5_faid"];
        }
    }
}

// ARC 版还原
// 作用：使用 CommonCrypto 对输入数据做对称加密（AES + PKCS7），返回 NSData
// 说明：a1 = 明文 NSData，a2 = key NSData
NSData *sub_1005D6E08(NSData *data, NSData *key){
    NSData *result = nil;
    if (data && key) {
        NSData *keyCopy = [key copy];
        NSData *dataCopy = [data copy];
        NSMutableData *outData = [NSMutableData dataWithLength:[dataCopy length] + 16];
        size_t outLength = 0;
        const void *keyBytes = [keyCopy bytes];
        size_t keyLength = [keyCopy length];
        const void *dataBytes = [dataCopy bytes];
        size_t dataLength = [dataCopy length];
        CCCryptorStatus status = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, keyBytes, keyLength, NULL, dataBytes, dataLength, [outData mutableBytes], [outData length], &outLength);
        if (status == kCCSuccess) {
            if (outLength < [outData length]) {
                [outData replaceBytesInRange:NSMakeRange(outLength, [outData length] - outLength) withBytes:NULL length:0];
            }
            result = [NSData dataWithData:outData];
        }
    }
    return result;
}


- (void)updateHardwareInfo {
    // 1. 获取DPI信息（如果未关闭）
    if ( {
        TuringGatheringXXQ *gathering = [self gathering];
        self->_dpi = [gathering getScreenDPIWithError:nil];
        [self setADValue:[NSString stringWithFormat:@"%llu", self->_dpi] forKey:@4];
    }
    
    // 2. 获取屏幕分辨率信息（如果未关闭）
    if ( {
        TuringGatheringXXQ *gathering = [self gathering];
        CGSize resolution = [gathering getScreenResolutionWithError:nil];
        self->_screenWidth = (int)resolution.width;
        self->_screenHeight = (int)resolution.height;
        
        [self setADValue:[NSString stringWithFormat:@"%d", self->_screenWidth] forKey:@5];
        [self setADValue:[NSString stringWithFormat:@"%d", self->_screenHeight] forKey:@6];
    }
    
    // 3. 获取越狱状态（如果未关闭）
    if ( {
        TuringGatheringXXQ *gathering = [self gathering];
        self->_isJailBroken = [gathering getIsJailbrokenWithError:nil];
        [self setADValue:[NSString stringWithFormat:@"%d", self->_isJailBroken] forKey:@17];
    }
    
    // 4. 获取物理内存信息（如果未关闭）
    if ( {
        TuringGatheringXXQ *gathering = [self gathering];
        long long memory = [gathering getPhysicalMemoryWithError:nil];
        self->_physicalMemory = [NSString stringWithFormat:@"%lld", memory];
        [self setADValue:self->_physicalMemory forKey:@18];
    }
    
    // 5. 获取磁盘大小信息（如果未关闭）
    if ( {
        TuringGatheringXXQ *gathering = [self gathering];
        long long diskSize = [gathering getHarddiskSizeWithError:nil];
        self->_diskS = [NSString stringWithFormat:@"%lld", diskSize];
        [self setADValue:self->_diskS forKey:@19];
    }
}

#pragma mark - 辅助方法

- (BOOL)isSettingEnabled:(NSString *)settingKey {
    TGGDTSettingManager *settingManager = [TGGDTSettingManager defaultManager];
    BOOL isClosed = [settingManager appBoolObjectForKey:settingKey];
    return isClosed;
}

- (void)setADValue:(NSString *)value forKey:(NSNumber *)key {
    NSMutableDictionary *adList = [self fetchADlist];
    [self synSafeSetObject:value forKey:key withContainer:adList];
}
@end