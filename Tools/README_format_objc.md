# formatObjCObject 公共工具使用说明

## 方法1：使用 frida-trace 的 -I 参数（推荐）

在运行 `frida-trace` 时，使用 `-I` 参数加载初始化脚本：

```bash
frida-trace -U -f com.kugou.kugou1002 -I Tools/format_objc.js -m "*[Qmeiegtm qmei_*]"
```

这样 `formatObjCObject` 函数会在所有 handler 文件加载之前被定义，所有 handler 都可以直接使用。

## 方法2：在 handler 文件中直接引用

如果 `-I` 参数不可用，可以在每个 handler 文件开头添加：

```javascript
// 加载公共格式化工具
rpc.exports = {}; // 确保 rpc 对象存在
try {
  eval(File.read('Tools/format_objc.js'));
} catch (e) {
  // 如果文件读取失败，使用内联版本
  // ... 函数定义 ...
}
```

## 方法3：使用全局作用域（最简单）

由于 frida-trace 的所有 handler 在同一个 JavaScript 上下文中运行，可以直接在 `format_objc.js` 中定义全局函数，然后通过 `-I` 加载。

## 使用示例

在任何 handler 文件中直接使用：

```javascript
defineHandler({
  onEnter(log, args, state) {
    const objcObj = new ObjC.Object(args[2]);
    log('👉 ' + formatObjCObject(objcObj));  // 直接使用，无需定义
  },
  
  onLeave(log, retval, state) {
    const objcObj = new ObjC.Object(retval);
    log('👈 ' + formatObjCObject(objcObj));
  }
});
```

## 注意事项

1. 使用 `-I` 参数时，确保路径相对于运行 `frida-trace` 的目录
2. 如果路径不对，可以使用绝对路径：`-I /Users/zb/gitCode/HookKuGou/Tools/format_objc.js`
3. 函数会在全局作用域中定义，所有 handler 都可以访问

