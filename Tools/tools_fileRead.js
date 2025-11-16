// 监控文件读取操作，定位哪里使用了 config.xml（极简版）
// 运行：frida -U -f com.tencent.QQMusic -l tools_fileRead.js

const TARGET = "config.xml";

function installHooks() {
    if (!ObjC.available) return;
    
    try {
        // 只 hook 最常用的 NSDictionary dictionaryWithContentsOfFile（读取 plist）
        const NSDictionary = ObjC.classes.NSDictionary;
        if (NSDictionary && NSDictionary["+ dictionaryWithContentsOfFile:"]) {
            Interceptor.attach(NSDictionary["+ dictionaryWithContentsOfFile:"].implementation, {
                onEnter: function(args) {
                    this._pathPtr = args[2];
                },
                onLeave: function(retval) {
                    try {
                        if (!this._pathPtr || this._pathPtr.isNull()) return;
                        
                        const path = ObjC.Object(this._pathPtr).toString();
                        if (path.indexOf(TARGET) === -1) return;
                        
                        const context = this.context;
                        
                        setTimeout(function() {
                            console.log("\n[NSDictionary dictionaryWithContentsOfFile] path:", path);
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
        
        // Hook NSData dataWithContentsOfFile（读取文件数据）
        const NSData = ObjC.classes.NSData;
        if (NSData && NSData["+ dataWithContentsOfFile:"]) {
            Interceptor.attach(NSData["+ dataWithContentsOfFile:"].implementation, {
                onEnter: function(args) {
                    this._pathPtr = args[2];
                },
                onLeave: function(retval) {
                    try {
                        if (!this._pathPtr || this._pathPtr.isNull()) return;
                        
                        const path = ObjC.Object(this._pathPtr).toString();
                        if (path.indexOf(TARGET) === -1) return;
                        
                        const context = this.context;
                        
                        setTimeout(function() {
                            console.log("\n[NSData dataWithContentsOfFile] path:", path);
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
        
        console.log("[OK] File read hooks installed");
    } catch (e) {
        console.log("[ERR]", e);
    }
}

// 延迟安装，等待应用完全启动
setTimeout(installHooks, 8000);
