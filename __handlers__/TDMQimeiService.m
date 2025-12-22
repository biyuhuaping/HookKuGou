
@interface TDMQimeiService : NSObject
@property (nonatomic, strong) TDMQimeiHandler *handler;
@end

@implementation TDMQimeiService

- (id)getQimei {
    id handler = [self handler];
    id qimeiContent = [handler qimeiContent];
    id result = [self qimeiContentWithSetting:qimeiContent];
    return result;
}