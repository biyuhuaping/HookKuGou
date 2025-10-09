// 用 Frida 同时 hook 多个类
// 运行方式： frida -U -n AppName -l hook_two_classes.js

ObjC.schedule(ObjC.mainQueue, function() {
    targets.forEach(function(cname){
        hookClassMethodsByOwnMethods(cname);
    });
    safePrint("[*] Hook setup complete for:", targets.join(", "));
});


// 安全打印，避免崩溃
function safePrint() {
    try {
        console.log.apply(console, arguments);
    } catch (e) {}
}

// 要 hook 的类（可修改）
var targets = [
    "ALAppLovinVideoViewController",
    "ALBaseVideoViewController",
    "NSProcessInfo",
    // "NSURLSession",
    // "SKStoreProductViewController",
    // "WKWebView",
    // "NSURL",
];

// 黑名单，防止刷屏
var methodBlacklist = [
    "new",
    "copyWithZone",
    "description",
    "debugDescription",
    "class",
    "superclass",
    "hash",
    "_groupSession",
    "_groupConfiguration",
    "defaultTaskGroup",
    "adDurationMillis",
    "sdk",
    "instance",
    "sdkKey",
    "arrayForKey",
    "numberForKey",
    "logger",
    "settingsManager",
    "integerForKey",
    "boolForKey",
    "setAdDurationMillis",
    "settings",
    "userDefaults",
    "currentAd",
];

// 通用 hook 方法
function hookClassMethodsByOwnMethods(className) {
    var cls = ObjC.classes[className];
    if (!cls) {
        safePrint("[-] Class not found:", className);
        return;
    }

    var methods = cls.$ownMethods;
    methods.forEach(function (methodName) {
        if (methodBlacklist.some(b => methodName.indexOf(b) >= 0)) {
            return; // 跳过黑名单方法
        }

        try {
            var impl = cls[methodName].implementation;
            Interceptor.attach(impl, {
                onEnter: function (args) {
                    // Objective-C 方法，第 2 个参数(args[2])开始才是真正的参数
                    // var argCount = m.split(":").length - 1;
                    // var parsedArgs = [];
                    // for (var i = 0; i < argCount; i++) {
                    //     parsedArgs.push(describeArg(args[2 + i]));
                    // }
                    // this.parsedArgs = parsedArgs;
                    // safePrint("[+] Enter", className, m, "args:", this.parsedArgs.join(", "));

                    // 打印调用栈
                    // var backtrace = Thread.backtrace(this.context, Backtracer.FUZZY)
                    //     .map(DebugSymbol.fromAddress)
                    //     .join("\n");
                    // console.log("[*] Call stack:\n" + backtrace);
                },
                onLeave: function (retval) {
                    // safePrint("[-] Leave", className, methodName, "Return:", describeArg(retval));
                    safePrint(className, methodName);//,"args:", this.parsedArgs.join(", "), "Return:", retval);//"args:", this.parsedArgs.join(", "),
                }
            });
        } catch (e) {
            safePrint("[!] Failed to hook", methodName, e);
        }
    });
}

// 永不崩溃（任何类型都至少 toString() 打印地址）
// OC 对象 → toString()
// C 字符串 → readUtf8String()
// SEL → SEL(name)
// 其他情况 → 原始指针/数值
function describeArg(arg) {
    try {
        if (!arg) return "<null>";
        if (arg.isNull && arg.isNull()) return "nil";

        // 1. Objective-C 对象
        try {
            if (ObjC.Object) {
                let o = ObjC.Object(arg);
                if (o) {
                    return o.toString();
                }
            }
        } catch (e) {
            // not an ObjC object
        }

        // 2. SEL (Objective-C selector)
        try {
            let selName = ObjC.selectorAsString(arg);
            if (selName && selName.length > 0) {
                return "SEL(" + selName + ")";
            }
        } catch (e) {}

        // 3. C string
        try {
            let cstr = arg.readUtf8String();
            if (cstr && cstr.length > 0) {
                return '"' + cstr + '"';
            }
        } catch (e) {}

        // 4. 标量 (int, float, double...)
        //    简单判断地址值大小，猜测它是标量
        try {
            let v = arg.toInt64();
            // 在 [-1e6, 1e6] 范围内的整数，可能是标量
            if (v > -1000000 && v < 1000000) {
                return v.toString();
            }
        } catch (e) {}

        try {
            let dv = arg.toDouble ? arg.toDouble() : null;
            if (dv !== null && !isNaN(dv)) {
                return dv.toString();
            }
        } catch (e) {}

        // 5. fallback: 显示 pointer
        return arg.toString();
    } catch (e) {
        return "<err " + e + ">";
    }
}




