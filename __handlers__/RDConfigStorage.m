  4431 ms  -[RDConfigStorage asyncLoadDiskWithGuid:0x281dd7700 env:0x1108aac28 completedBlock:0x16efa9cd8]
  4431 ms  0x10dbcaf98 kugou!-[RDConfigStorage initWithSettings:delegate:]
0x10dbc5340 kugou!-[RDConfigManager initWithSettings:]
0x10dbd359c kugou!-[RDeliverySDK initWithSettings:]
0x10dbd3464 kugou!+[RDeliverySDK createSDKWithSettings:]
0x10dbf8a08 kugou!-[ZBHTextWindowCount launchRDelivery]
0x10dbf9308 kugou!0xcda5308 (0x10cda5308)
0x1ca6027c8 libdispatch.dylib!_dispatch_client_callout
0x1ca5e4b54 libdispatch.dylib!_dispatch_lane_barrier_sync_invoke_and_complete
0x10dbf8c78 kugou!-[ZBHTextWindowCount runOnManagerQueueSync:]
0x10dbf9284 kugou!-[ZBHTextWindowCount initSDK:]
0x10dbea760 kugou!0xcd96760 (0x10cd96760)
0x10dbea9dc kugou!0xcd969dc (0x10cd969dc)
0x1ca6027c8 libdispatch.dylib!_dispatch_client_callout
0x1ca5d2f40 libdispatch.dylib!_dispatch_once_callout
0x10dbea7ec kugou!0xcd967ec (0x10cd967ec)
0x107bd9d80 kugou!0x6d85d80 (0x106d85d80)


- (void)asyncLoadDiskWithGuid:(NSString *)guid env:(NSString *)env completedBlock:(void (^)(void))completedBlock {
    // 1. 在内存队列上同步执行准备阶段
    dispatch_queue_t memoryQueue = [self memoryQueue];
    dispatch_barrier_sync(memoryQueue, ^{
        // 记录日志
        [self logWithTag:@"[RDelivery][RDConfigStorage]" 
                fileName:@"RDConfigStorage.m" 
              lineNumber:270 
                function:@"-[RDConfigStorage asyncLoadDiskWithGuid:env:completedBlock:]" 
                 content:@"准备开始读取磁盘阶段，切换环境，guid:%@, env:%@", guid, env];
        
        // 设置配置信息
        [self.settings setGuid:guid];
        [self.settings setEnvId:env];
        
        // 清空配置信息
        NSDictionary *configInfos = [self.settings configInfos];
        [configInfos removeAllObjects];
        
        // 设置上下文
        [self.settings setContext:nil];
    });
    
    // 2. 在磁盘队列上异步执行磁盘读取
    dispatch_queue_t diskQueue = [self diskQueue];
    dispatch_async(diskQueue, ^{
        // 标记开始加载磁盘
        [self.settings setIsLoadingDisk:YES];
        
        // 生成存储标识符
        NSString *storageIdentifier = [self.settings storeIdentifierWithGuid:guid env:env];
        NSString *storageName = [self.settings storageNameWithIdentifier:storageIdentifier];
        
        // 记录开始日志
        [self logWithTag:@"[RDelivery][RDConfigStorage]" 
                fileName:@"RDConfigStorage.m" 
              lineNumber:297 
                function:@"-[RDConfigStorage asyncLoadDiskWithGuid:env:completedBlock:]" 
                 content:@"读取磁盘开始，storageName:%@", storageName];
        
        // 同步执行磁盘读取
        dispatch_sync([self kvStorageQueue], ^{
            // 检查临时存储
            id tempStorage = [self.settings readDiskTempKvStorage];
            NSString *tempStorageName = [tempStorage storageName];
            
            if ([tempStorageName isEqualToString:storageName]) {
                // 如果临时存储名称匹配，直接使用临时存储
                [self.settings setKvStorage:tempStorage];
                [self.settings setReadDiskTempKvStorage:nil];
            } else {
                // 否则创建新的存储
                id mediatorCenter = [self.settings mediatorCenter];
                id kvMediator = [mediatorCenter kvMediator];
                id newStorage = [kvMediator createKVStorageWithName:storageName];
                [self.settings setKvStorage:newStorage];
            }
            
            // 如果记录拉取时间，创建拉取时间存储
            if ([self.settings isRecordPullTime]) {
                NSString *pullTimeIdentifier = [self.settings pullTimeStoreIdentifierWithGuid:guid env:env];
                NSString *pullTimeStorageName = [self.settings storageNameWithIdentifier:pullTimeIdentifier];
                id pullTimeStorage = [kvMediator createKVStorageWithName:pullTimeStorageName];
                [self.settings setPullTimeKVStorage:pullTimeStorage];
            }
        });
        
        // 创建结果字典
        NSMutableDictionary *resultDict = [NSMutableDictionary dictionary];
        
        // 获取所有配置键
        NSArray *allConfigKeys = [self.settings allConfigKeys];
        
        // 遍历所有配置键，从磁盘读取数据
        for (NSString *key in allConfigKeys) {
            @autoreleasepool {
                // 从KV存储获取数据
                id kvStorage = [self.settings kvStorage];
                NSData *data = [kvStorage dataForKey:key];
                
                if (data.length > 0) {
                    // 尝试安全解档（使用允许的类列表）
                    NSSet *allowedClasses = [NSSet setWithObjects:
                        [RDConfigInfo class],
                        [RDABTestInfo class], 
                        [NSString class],
                        [NSDictionary class],
                        [NSArray class],
                        [NSNumber class], nil];
                    
                    NSError *error = nil;
                    id unarchivedObject = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses 
                                                                              fromData:data 
                                                                                 error:&error];
                    
                    if (error) {
                        // 记录解档错误
                        [self logWithTag:@"[RDelivery][RDConfigStorage]" 
                                fileName:@"RDConfigStorage.m" 
                              lineNumber:318 
                                function:@"-[RDConfigStorage asyncLoadDiskWithGuid:env:completedBlock:]" 
                                 content:@"读取本地配置解析失败！配置key:%@, error:%@ 尝试兜底处理", key, error];
                        
                        // 尝试传统解档方式
                        unarchivedObject = [NSKeyedUnarchiver unarchiveObjectWithData:data];
                    }
                    
                    if (unarchivedObject) {
                        // 成功解档，存储到结果字典
                        [resultDict setObject:unarchivedObject forKey:key];
                    } else {
                        // 解档失败，删除损坏的数据
                        [kvStorage removeValueForKey:key];
                        [kvStorage trim];
                    }
                }
            }
        }
        
        // 记录读取结果
        [self logWithTag:@"[RDelivery][RDConfigStorage]" 
                fileName:@"RDConfigStorage.m" 
              lineNumber:334 
                function:@"-[RDConfigStorage asyncLoadDiskWithGuid:env:completedBlock:]" 
                 content:@"读取磁盘配置:%@", [resultDict allValues]];
        
        // 3. 在内存队列上同步执行完成阶段
        dispatch_queue_t memoryQueue = [self memoryQueue];
        dispatch_barrier_sync(memoryQueue, ^{
            // 记录完成日志
            [self logWithTag:@"[RDelivery][RDConfigStorage]" 
                    fileName:@"RDConfigStorage.m" 
                  lineNumber:344 
                    function:@"-[RDConfigStorage asyncLoadDiskWithGuid:env:completedBlock:]" 
                     content:@"读取磁盘完成，storageName:%@", storageName];
            
            // 标记加载完成
            [self.settings setIsLoadingDisk:NO];
            
            // 设置配置信息
            [self.settings setGuid:guid];
            [self.settings setEnvId:env];
            [self.settings setConfigInfos:resultDict];
            
            // 从存储中读取上下文
            id kvStorage = [self.settings kvStorage];
            NSString *context = [kvStorage stringForKey:@"__[RDelivery]RDRequestContextKey"];
            [self.settings setContext:context];
        });
        
        // 4. 执行完成回调（在主线程）
        if (completedBlock) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completedBlock();
            });
        }
    });
}