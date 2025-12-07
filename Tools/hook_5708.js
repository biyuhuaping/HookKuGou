//使用方式：frida -U -f com.kugou.kugou1002 -l Tools/hook_5708.js

// Hook sub_10CC45708 监控并篡改上报字段
// const funcAddr = ptr("0x10CC45708");
// Interceptor.attach(funcAddr, {
//     onEnter: function(args) {
//         console.log("\n=== sub_10CC45708 调用 ===");
//         const dict = new ObjC.Object(args[0]);
//         const key = new ObjC.Object(args[1]);
//         const value = new ObjC.Object(args[2]);
//         console.log("字典：", dict);
//         console.log("Key：", key);
//         console.log("原始 Value：", value);
        
//         // 篡改 Value 为自定义字符串
//         if (key.toString() === "q16") {
//             const fakeValue = ObjC.classes.NSString.stringWithUTF8String_("bjdx8343kd9f2999008988");
//             args[2] = fakeValue; // 替换参数
//             console.log("篡改后 Value：", fakeValue);
//         }
//     }
// });

//sub_107C0A718(dict, q16Key, q16Value);
var addr = Module.findBaseAddress("kugou"); 
var f = addr.add(0x7C0A718);   // sub_107C0A718 = 0x107C0A718
Interceptor.attach(f, {
    onEnter(args) {
        const dict = new ObjC.Object(args[0]);
        const key = new ObjC.Object(args[1]);
        const value = new ObjC.Object(args[2]);
        console.log("字典：", dict, ("(" + dict.$className + ")"));
        console.log("Key：", key, ("(" + key.$className + ")"));
        console.log("原始 Value：", value, ("(" + value.$className + ")"));
    },
    onLeave(retval) {
        const object = new ObjC.Object(retval);
        console.log("sub_107C0A718 ret=", object.toString());
    }
});
