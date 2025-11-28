# Handler 文件批量更新总结

## 更新完成 ✅

已成功将 `__handlers__` 目录下所有需要更新的 JS 文件统一改为使用 `formatObjCObject` 函数输出日志。

## 更新统计

- ✅ **已更新**: 70 个文件
- ⏭️ **已跳过**: 2078 个文件（已使用 formatObjCObject 或无需更新）
- ❌ **错误**: 0 个文件

## 更新内容

### 替换的模式

1. **旧格式**: `log('👉'+ objcObj.toString() + '（' + objcObj.$className + '）')`
   - **新格式**: `log('👉 ' + formatObjCObject(objcObj))`

2. **旧格式**: `log('👈: '+ objcObj.$className +" "+ objcObj.toString() + '\n')`
   - **新格式**: `log('👈 ' + formatObjCObject(objcObj) + '\n')`

3. **修复**: `ObjC.Object()` → `new ObjC.Object()`

## 使用方法

### 运行 frida-trace 时加载公共工具

```bash
# 方法1: 使用便捷脚本（推荐）
./Tools/frida-trace-with-format.sh -U -f com.kugou.kugou1002 -m "*[Qmeiegtm qmei_*]"

# 方法2: 手动指定 -I 参数
frida-trace -U -f com.kugou.kugou1002 -I Tools/format_objc.js -m "*[Qmeiegtm qmei_*]"
```

### 在 handler 中使用

所有 handler 文件现在都可以直接使用 `formatObjCObject`，无需定义：

```javascript
defineHandler({
  onEnter(log, args, state) {
    const objcObj = new ObjC.Object(args[2]);
    log('👉 ' + formatObjCObject(objcObj));  // 直接使用
  },
  
  onLeave(log, retval, state) {
    const objcObj = new ObjC.Object(retval);
    log('👈 ' + formatObjCObject(objcObj) + '\n');
  }
});
```

## 优势

1. **统一格式**: 所有 handler 使用相同的格式化方式
2. **智能识别**: 根据对象类型自动选择最佳输出方式
3. **易于维护**: 只需在一个文件中维护格式化逻辑
4. **自动加载**: 通过 `-I` 参数自动加载，无需修改每个文件

## 更新的主要目录

- `__handlers__/Qmeiegtm/` - 多个文件已更新
- `__handlers__/UICKeyChainStore/` - 多个文件已更新
- `__handlers__/OstarService/` - 多个文件已更新
- `__handlers__/KGTencentStatistics/` - 多个文件已更新
- 以及其他多个目录

## 注意事项

⚠️ **重要**: 使用 frida-trace 时必须通过 `-I` 参数加载 `Tools/format_objc.js`，否则 `formatObjCObject` 函数将不可用。

如果忘记加载，handler 会报错：`ReferenceError: formatObjCObject is not defined`

