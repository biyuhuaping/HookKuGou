-[KGDeviceFPManager checkUpdateWithSmallPackageWithBlock:isSmallPackage:]//static void sub_105582CD0

static void sub_105582CD0(int64_t ctx)
{
    // 1. Dao
    KGDeviceFPHttpDao *dao = [[KGDeviceFPHttpDao alloc] initKGAppMoudleWithConfiguration:nil];

    // 2. Shared device id
    KGSeverShareDeviceIDGen *gen = [TrackerLiteContext setBaseContext:[KGSeverShareDeviceIDGen class]];

    NSString *sharedID = [gen getLocalServerSharedDeviceIDString];
    BOOL isSmallPackage = *(uint8_t *)(ctx + 0x30);

    id error = nil;
    NSDictionary *result = [dao requestDeviceDFIDWith:sharedID isSmallPackage:isSmallPackage error:&error];

    id errorCopy = [error copy];
    if (!errorCopy) {
        id device = *(id *)(ctx + 0x20);

        NSString *dfid = [result stringForKeyKGSafe:@"dfid"];
        [device setDeviceFingerprintID:dfid];

        NSNumber *scheme = [result objectForKeyKGSafe:@"scheme" class:[NSNumber class]];
        *(uint8_t *)((uint64_t)device + 0x27) = [scheme boolValue];
    }

    // 3. main queue callback
    dispatch_async(dispatch_get_main_queue(), ^{
        id param = [*(id *)(ctx + 0x28) copy];
        invoke(param);
    });
}
