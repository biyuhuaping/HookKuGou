- (TDMQimeiContent *)qimeiContent {
    [_lock lock];
    
    if (_qimeiContent) {
        [_lock unlock];
        return [_qimeiContent retain];
    }
    
    NSString *appkey = [self appkey];
    NSError *error = nil;
    NSString *qimeiJson = [TDMQimeiBundleUtil getQimeiJsonWithAppkey:appkey error:&error];
    
    if (error) {
        error = nil;
        qimeiJson = [TDMQimeiBundleUtil getQimeiJsonWithAppkey:appkey error:&error];
    }
    
    TDMQimeiContent *content = [[TDMQimeiContent alloc] initWithQimeiJson:qimeiJson];
    _qimeiContent = content;
    
    [_lock unlock];
    
    if (error) {
        NSError *customError = [NSError errorWithDomain:@"com.tencent.QimeiHttpsErrorDomain" code:1006 userInfo:@{NSLocalizedDescriptionKey: @(error.code)}];
        [_errorReporter postErrorWithError:customError];
    }
    
    return content;
}

- (void)setQimeiContent:(TDMQimeiContent *)content {
    [_lock lock];
    
    _qimeiContent = content;
    
    NSString *qimeiJson = [content qimeiJson];
    NSString *appkey = [self appkey];
    NSError *error = nil;
    
    BOOL success = [TDMQimeiBundleUtil saveQimeiJson:qimeiJson withAppkey:appkey error:&error];
    
    if (!success && error) {
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            NSError *customError = [NSError errorWithDomain:@"com.tencent.QimeiHttpsErrorDomain" code:1006 userInfo:@{NSLocalizedDescriptionKey: @(error.code)}];
            [_errorReporter postErrorWithError:customError];
        });
    }
    
    [_lock unlock];
}