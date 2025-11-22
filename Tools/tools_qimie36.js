// 监听任何类调用包含 qimie36 的方法（安全版）
// 运行：frida -U -f com.tencent.QQMusic -l tools_qimie36.js

// ObjC.schedule(ObjC.mainQueue, function () {
//     var cls = ObjC.classes.GDTTangramHostDeviceInfo;
//     var method = cls["- setQimei36:"];

//     Interceptor.attach(method.implementation, {
//         onEnter: function (args) {
//             console.log("setQimei36 called, original:", new ObjC.Object(args[2]));

//             // 写入伪造值
//             var fake = ObjC.classes.NSString.stringWithUTF8String_("FAKE_QIMEI36_ABC");
//             args[2] = fake;
//         }
//     });
// });

var cls = ObjC.classes.GDTTangramHostDeviceInfo;
Interceptor.attach(cls["- setQimei36:"].implementation, {
    onEnter() {
        console.log("setQimei36 called");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n"));
    }
});
