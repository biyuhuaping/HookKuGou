@implementation UICKeyChainStore

// +[UICKeyChainStore setString:forKey:service:accessGroup:]
+ (BOOL)setString:(NSString *)string forKey:(NSString *)key service:(NSString *)service accessGroup:(NSString *)accessGroup
{
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    return [self setData:data forKey:key service:service accessGroup:accessGroup];
}


@end