// 监控文件写入操作，定位写入到指定路径的代码（极简版）
// 运行：frida -U -f com.tencent.QQMusic -l tools_fileWrite.js

const TARGET = "config.xml";

function installHooks() {
    if (!ObjC.available) return;
    
    try {
        // 只 hook 最常用的 NSData writeToFile
        const NSData = ObjC.classes.NSData;
        if (NSData && NSData["- writeToFile:atomically:"]) {
            Interceptor.attach(NSData["- writeToFile:atomically:"].implementation, {
                onEnter: function(args) {
                    this._pathPtr = args[2];
                },
                onLeave: function(retval) {
                    try {
                        if (!this._pathPtr || this._pathPtr.isNull()) return;
                        
                        const path = ObjC.Object(this._pathPtr).toString();
                        if (path.indexOf(TARGET) === -1) return;
                        
                        const context = this.context;
                        const result = retval;
                        
                        // 延迟输出，避免在 hook 回调中直接调用
                        setTimeout(function() {
                            console.log("\n[NSData writeToFile] path:", path);
                            console.log("  result:", result ? "SUCCESS" : "FAILED");
                            try {
                                const bt = Thread.backtrace(context, Backtracer.FUZZY)
                                    .map(DebugSymbol.fromAddress)
                                    .join("\n");
                                console.log("  backtrace:\n" + bt);
                            } catch (e) {}
                        }, 0);
                    } catch (e) {}
                }
            });
        }
        
        // Hook NSDictionary writeToFile（plist 常用）
        const NSDictionary = ObjC.classes.NSDictionary;
        if (NSDictionary && NSDictionary["- writeToFile:atomically:"]) {
            Interceptor.attach(NSDictionary["- writeToFile:atomically:"].implementation, {
                onEnter: function(args) {
                    this._pathPtr = args[2];
                },
                onLeave: function(retval) {
                    try {
                        if (!this._pathPtr || this._pathPtr.isNull()) return;
                        
                        const path = ObjC.Object(this._pathPtr).toString();
                        if (path.indexOf(TARGET) === -1) return;
                        
                        const context = this.context;
                        const result = retval;
                        
                        setTimeout(function() {
                            console.log("\n[NSDictionary writeToFile] path:", path);
                            console.log("  result:", result ? "SUCCESS" : "FAILED");
                            try {
                                const bt = Thread.backtrace(context, Backtracer.FUZZY)
                                    .map(DebugSymbol.fromAddress)
                                    .join("\n");
                                console.log("  backtrace:\n" + bt);
                            } catch (e) {}
                        }, 0);
                    } catch (e) {}
                }
            });
        }
        
        console.log("[OK] File write hooks installed");
    } catch (e) {
        console.log("[ERR]", e);
    }
}

// 延迟安装
setTimeout(installHooks, 5000);
