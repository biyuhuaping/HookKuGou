if (!ObjC.available) {
    console.log("Objective-C Runtime 不可用");
    return;
  }
  
  var UICKeyChainStore = ObjC.classes.UICKeyChainStore;
  if (!UICKeyChainStore) {
    console.log("未找到 UICKeyChainStore 类，确认当前进程已加载相关模块");
    return;
  }
  
  // 主线程上调用，避免 UI 线程安全问题
  ObjC.schedule(ObjC.mainQueue, function () {
    try {
      UICKeyChainStore.removeAllItems();
      console.log("[+] 已调用 +[UICKeyChainStore removeAllItems]");
    } catch (e) {
      console.log("[-] 调用失败: " + e);
    }
  });