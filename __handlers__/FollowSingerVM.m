- (void)addNotification
{
    NSNotificationCenter *center = [NSNotificationCenter defaultCenter];

    // follow
    [center addObserver:self selector:@selector(followActionNotification:) name:@"kNotificationFollowSingerAction" object:nil];

    // unfollow
    [center addObserver:self selector:@selector(followActionNotification:) name:@"kNotificationUnFollowSingerAction" object:nil];

    // logout
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(logoutHandler:) name:@"user_login_out" object:nil];

    // login
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(loginHandler:) name:@"user_login" object:nil];
}
