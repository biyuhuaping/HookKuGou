copy params
│
├─ 日志输出（debug / report / developer）
│
├─ 构建 TGGDTLoadAdRequestBaseData
│   └─ extReq 存在？
│
├─ 是否允许获取 jsbundle 信息
│   └─ YES → 构建 device_ext
│       ├─ 收集各模块 version
│       ├─ scene → module_name
│       ├─ landing_page_js_bundle_version
│       ├─ style_render_engine_js_bundle_version
│       └─ 写回 extReq.device_ext
│
└─ return [extReq toMap]


+ (NSDictionary *)getTangramDeviceInfoWithScene:(TGGDTGetDeviceParams *)params
{
    // ---------- 1. copy 参数 ----------
    TGGDTGetDeviceParams *copiedParams = [HippyI18nUtils copy:params];

    // ---------- 2. 打印日志（原代码大量日志，这里只保留结构） ----------
    if ([TGGDTLogUtil isEnableDebugLog]) {
        [TGGDTLogUtil log:[NSString stringWithFormat:@"getTangramDeviceInfo params:%@", copiedParams]];
    }

    if ([TGGDTLogUtil isEnableReportLog]) {
        [TGGDTLogUtil reportSDKGDTlog:[NSString stringWithFormat:@"getTangramDeviceInfo scene:%ld", (long)copiedParams.scene]];
    }

    if ([TGGDTLogUtil isDeveloperLogEnable]) {
        [TGGDTLogUtil outputToAppDeveloperLevel:[NSString stringWithFormat:@"scene:%ld", (long)copiedParams.scene]];
    }

    // ---------- 3. 构建 BaseData ----------
    TGGDTLoadAdRequestBaseData *baseData = [[TGGDTLoadAdRequestBaseData alloc] initWithContainUA:YES loadAdParams:copiedParams.loadAdParams];

    if (!baseData) {
        return @{};
    }

    // ---------- 4. 取 extReq ----------
    TGGDTLoadAdRequestExtData *extReq = baseData.extReq;
    if (!extReq) {
        return @{};
    }

    // ---------- 5. 判断是否禁止获取 jsbundle ----------
    BOOL donotGetJsbundleInfo = [[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"donotGetJsbundleInfo"];

    if (!donotGetJsbundleInfo) {
        // ---------- 6. device_ext ----------
        NSMutableDictionary *deviceExt = [NSMutableDictionary dictionary];

        // ---------- 7. jsbundle_info ----------
        NSMutableDictionary *jsbundleInfo = [NSMutableDictionary dictionary];

        NSArray *bundleIds = @[
            @"pcad-reward",
            @"pcad-reward-lgt",
            @"pcad-native",
            @"GDTTangramSplash-mosaic",
            @"explicit-ad-lgt"
        ];

        for (NSString *bundleId in bundleIds) {
            DKDynamicBundleItem *item = [[DKDynamicBundleManger setBaseContext] moduleItemWithId:bundleId];

            NSString *version = item.version;
            if (version.length > 0) {
                jsbundleInfo[bundleId] = version;
            }
        }

        if (jsbundleInfo.count > 0) {
            NSString *json = [TGGDTJSONUtil jsonStringFromDic:jsbundleInfo];

            BOOL encode = [[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"jsbundleInfoEncode"];

            if (encode) {
                json = [json stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
            }

            deviceExt[@"jsbundle_info"] = json;
        }

        // ---------- 8. landing_page_js_bundle_version ----------
        NSMutableArray *landingPageBundles = [NSMutableArray array];

        DKDynamicBundleItem *canvasItem = [[DKDynamicBundleManger setBaseContext] moduleItemWithId:@"ad-dynamic-canvas"];

        if (canvasItem.version.length > 0) {
            [landingPageBundles addObject:@{
                @"render_engine_type": @1,
                @"js_bundle_version": canvasItem.version,
                @"module_name": @"ad-dynamic-canvas"
            }];
        }

        if (landingPageBundles.count > 0) {
            deviceExt[@"landing_page_js_bundle_version"] = [landingPageBundles copy];
        }

        // ---------- 9. module_name（由 scene 决定） ----------
        NSString *moduleName = @"";

        switch (copiedParams.scene) {
            case 1: moduleName = @"splash"; break;
            case 2: moduleName = @"native"; break;
            case 3: moduleName = @"interstitial"; break;
            case 4: moduleName = @"reward"; break;
            default: break;
        }

        if (moduleName.length > 0) {
            deviceExt[@"module_name"] = moduleName;
        }

        // ---------- 10. style_render_engine_js_bundle_version ----------
        BOOL useNewDynamicProtocol = [[TGGDTSettingManager defaultManager] appBoolObjectForKey:@"useNewDynamicProtocol"];

        if (useNewDynamicProtocol) {
            NSMutableArray *styleBundles = [NSMutableArray array];

            void (^addBundle)(NSString *, NSNumber *) =
            ^(NSString *bundleId, NSNumber *engineType) {
                DKDynamicBundleItem *item =
                    [[DKDynamicBundleManger setBaseContext]
                        moduleItemWithId:bundleId];
                if (item.version.length > 0) {
                    [styleBundles addObject:@{
                        @"render_engine_type": engineType,
                        @"js_bundle_version": item.version,
                        @"module_name": bundleId
                    }];
                }
            };

            NSInteger scene = copiedParams.scene;

            if (scene == 0 || scene == 1) {
                addBundle(@"GDTTangramSplash-mosaic", @1);
            }
            if (scene == 0 || scene == 3) {
                addBundle(@"explicit-ad-lgt", @2);
            }
            if (scene == 0 || scene == 4) {
                addBundle(@"pcad-reward", @1);
            }
            if (scene == 0 || scene == 2) {
                addBundle(@"pcad-native", @1);
            }
            if (scene == 0 || scene == 4) {
                addBundle(@"pcad-reward-lgt", @1);
            }

            if (styleBundles.count > 0) {
                deviceExt[@"style_render_engine_js_bundle_version"] = [styleBundles copy];
            }
        }

        // ---------- 11. 写回 extReq ----------
        extReq.device_ext = [deviceExt copy];
    }

    // ---------- 12. 返回 ----------
    return [extReq toMap];
}
