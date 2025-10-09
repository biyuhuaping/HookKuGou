// 整个 window 的层级，所有view层级
// ObjC.schedule(ObjC.mainQueue, function(){
//     const window = ObjC.classes.UIWindow.keyWindow();
//     const ui = window.recursiveDescription().toString();
//     // send({ ui: ui });
//     console.log(ui); // 这里会直接打印，保留换行
// });

//只想看当前控制器（VC）的 view 层级
ObjC.schedule(ObjC.mainQueue, function () {
    // 拿到 rootViewController
    const rootVC = ObjC.classes.UIApplication.sharedApplication().keyWindow().rootViewController();

    // 获取当前最上层可见的 VC
    function topViewController(vc) {
        if (!vc) return null;
        if (vc.presentedViewController()) {
            return topViewController(vc.presentedViewController());
        } else if (vc.isKindOfClass_(ObjC.classes.UINavigationController)) {
            return topViewController(vc.visibleViewController());
        } else if (vc.isKindOfClass_(ObjC.classes.UITabBarController)) {
            return topViewController(vc.selectedViewController());
        } else {
            return vc;
        }
    }
    console.log("层级层级层级层级");
    const topVC = topViewController(rootVC);
    if (topVC) {
        const desc = topVC.view().recursiveDescription().toString();
        console.log("===== 当前控制器:", topVC.toString(), "=====");
        console.log(desc);
    } else {
        console.log("未找到顶层控制器");
    }
});


// ObjC.schedule(ObjC.mainQueue, function(){
//     const window = ObjC.classes.UIWindow.keyWindow();
//     const rootControl = window.rootViewController();
//     const control = rootControl['- _printHierarchy']();
//     // send({ ui: control.toString() });
//     console.log(control.toString() ); // 这里会直接打印，保留换行
// });

// function handleMessage(message) {
//     var order = message.substring(0, 1);
//     var command = '';

//     switch (order) {
//         case 'n':
//             command = message.substring(2);

//             var view = new ObjC.Object(ptr(command));
//             var nextResponder = view.nextResponder();

//             nextResponder = new ObjC.Object(ptr(nextResponder));

//             var deep = 0;
//             var pre = '';

//             while (nextResponder) {
//                 pre += '-';
//                 send({ ui: pre + '>' + nextResponder.toString() });

//                 nextResponder = nextResponder.nextResponder();
//                 nextResponder = new ObjC.Object(ptr(nextResponder));
//             }
//             break;
//         default:
//             send({ ui: 'error command' });
//     }
// }
