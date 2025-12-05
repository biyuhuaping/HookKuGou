// Hook sub_10CC45708 监控并篡改上报字段
const funcAddr = ptr("0x10CC45708");
Interceptor.attach(funcAddr, {
    onEnter: function(args) {
        console.log("\n=== sub_10CC45708 调用 ===");
        const dict = new ObjC.Object(args[0]);
        const key = new ObjC.Object(args[1]);
        const value = new ObjC.Object(args[2]);
        console.log("字典：", dict);
        console.log("Key：", key);
        console.log("原始 Value：", value);
        
        // 篡改 Value 为自定义字符串
        if (key.toString() === "q16") {
            const fakeValue = ObjC.classes.NSString.stringWithUTF8String_("bjdx8343kd9f2999008988");
            args[2] = fakeValue; // 替换参数
            console.log("篡改后 Value：", fakeValue);
        }
    }
});