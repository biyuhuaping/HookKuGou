// if (!ObjC.available) {
//     console.log("Objective-C Runtime 不可用");
//     return;
//   }
  
//   var UICKeyChainStore = ObjC.classes.UICKeyChainStore;
//   if (!UICKeyChainStore) {
//     console.log("未找到 UICKeyChainStore 类，确认当前进程已加载相关模块");
//     return;
//   }
  
//   // 主线程上调用，避免 UI 线程安全问题
//   ObjC.schedule(ObjC.mainQueue, function () {
//     try {
//       UICKeyChainStore.removeAllItems();
//       console.log("[+] 已调用 +[UICKeyChainStore removeAllItems]");
//     } catch (e) {
//       console.log("[-] 调用失败: " + e);
//     }
//   });

// hook_qmei_e948ze8.js
if (!ObjC.available) {
  console.log("ObjC runtime 不可用");
  return;
}

const cls = ObjC.classes.Qmeiegtm;
if (!cls || !cls["- qmei_e948ze8:code:"]) {
  console.log("找不到 -[Qmeiegtm qmei_e948ze8:code:]");
  return;
}

Interceptor.attach(cls["- qmei_e948ze8:code:"].implementation, {
  onEnter(args) {
    // args[0] = self, args[1] = _cmd, args[2] = 参数1, args[3] = 参数2
    this.arg1 = args[2];
    this.arg2 = args[3];

    console.log("=== Enter qmei_e948ze8:code: ===");
    printValue("arg0 (self)", args[0]);
    printValue("arg1 (param)", args[2]);
    printValue("arg2 (code)", args[3]);

    // 如需堆栈：
    // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
    //   .map(DebugSymbol.fromAddress).join("\n"));
  },

  onLeave(retval) {
    console.log("--- Leave qmei_e948ze8:code: ---");
    printValue("retval", retval);
    console.log("");
  }
});

function printValue(tag, ptrValue) {
  if (ptrValue.isNull()) {
    console.log(`${tag}: nil`);
    return;
  }

  try {
    const obj = new ObjC.Object(ptrValue);
    console.log(`${tag}: ${obj.toString()} (${obj.$className})`);
  } catch (e) {
    console.log(`${tag}: <非 ObjC 对象 ${ptrValue}，转换失败: ${e}>`);
  }
}