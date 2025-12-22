- (instancetype)initWithQimeiJson:(NSString *)qimeiJson {
    self = [super init];
    if (self) {
        if (!qimeiJson || [qimeiJson length] == 0) {
            _qimeiJson = qimeiJson;
            return self;
        }
        
        NSData *jsonData = [qimeiJson dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSDictionary *jsonDict = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingMutableContainers error:&error];
        
        if (jsonDict) {
            NSString *a3Value = jsonDict[@"A3"];
            
            NSString *firstKey = @"A3";
            NSString *secondKey = @"A153";
            
            if (!a3Value) {
                firstKey = @"q16";
                secondKey = @"q36";
            }
            
            if ([jsonDict count] >= 2) {
                NSString *firstValue = jsonDict[firstKey];
                NSString *secondValue = jsonDict[secondKey];
                
                _firstValue = firstValue;
                _secondValue = secondValue;
            } else {
                _qimeiJson = qimeiJson;
            }
        } else {
            _qimeiJson = qimeiJson;
        }
        
        _qimeiJson = qimeiJson;
    }
    return self;
}