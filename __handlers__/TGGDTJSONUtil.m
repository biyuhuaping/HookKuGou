0x11a4aa574 KGSafeKit!+[NSJSONSerialization(kgSwizzleGuardSafe) dataWithJSONObjectSafe:options:error:]
0x11d2a5ad0 HookKuGou.dylib!hook_NSJSONSerialization_dataWithJSONObject_options_error_
0x103575588 kugou!+[TGGDTJSONUtil jsonStringFromObject:]
0x1035757fc kugou!+[TGGDTJSONUtil jsonDataFromObject:]
0x1035ecfc8 kugou!0x684fc8 (0x100684fc8)+[TGGDTSDKServerService updateNewSetting]



+ (NSData *)jsonDataFromObject:(id)object{
    NSString *jsonString = [self jsonStringFromObject:object];
    NSData *data = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    return data;
}
