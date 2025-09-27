if (ObjC.available) {
    const cls = ObjC.classes.TMEAdHttpManager;
    const sel = "- inner_startRequest:originHttpStrategy:httpStrategy:isIpDirect:isRetrying:retryTimes:errorRecord:success:failure:";

    if (cls && cls[sel]) {
        Interceptor.attach(cls[sel].implementation, {
            onEnter: function (args) {
                // args[0] = self
                // args[1] = selector
                // args[2] = level (NSInteger)
                // args[3] = moduleName (NSString *)
                // args[4] = format (NSString *)

                const selfObj = new ObjC.Object(args[0]);
                const level = args[2].toInt32();
                const moduleName = new ObjC.Object(args[3]).toString();
                const format = new ObjC.Object(args[4]).toString();
                const format1 = new ObjC.Object(args[5]).toString();
                const format2 = new ObjC.Object(args[6]).toString();

                console.log("\n[Hook]", sel);
                console.log("  self:", selfObj.$className);
                console.log("  level:", level);
                // console.log("  moduleName:", moduleName);
                // console.log("  format:", format);
                // console.log("  format1:", format1);
                // console.log("  format2:", format2);
            },
            onLeave: function (retval) {
                console.log("  return:", retval);
            }
        });
    } else {
        console.log("❌ Method not found!");
    }
}
