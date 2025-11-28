/**
 * Objective-C 对象格式化工具
 * 根据对象类型自动选择最合适的输出方式
 * 
 * 使用方法：
 * 1. 在 frida-trace 中使用 -I 参数加载：frida-trace -I Tools/format_objc.js ...
 * 2. 或者在 handler 文件中直接包含此文件内容
 * 注意：formatObjCObject 函数通过 frida-trace -I Tools/format_objc.js 加载
 * 使用方式：frida-trace -U -f com.kugou.kugou1002 -I Tools/format_objc.js -m "*[Qmeiegtm qmei_*]"
 */

// 根据类型格式化输出（全局函数，供所有 handler 使用）
function formatObjCObject(objcObj) {
  if (!objcObj || objcObj.isNull()) {
    return 'nil';
  }
  
  const className = objcObj.$className;
  let output = '';
  
  try {
    // NSString 类型
    if (className === 'NSString' || className === '__NSCFString' || className === '__NSCFConstantString' || className === 'NSMutableString') {
      output = objcObj.toString();
    }
    // NSData 类型
    else if (className === 'NSData' || className === '__NSCFData' || className === 'NSMutableData') {
      const dataLength = objcObj.length();
      const dataBytes = objcObj.bytes();
      
      // 尝试 UTF-8 字符串
      try {
        const utf8String = Memory.readUtf8(dataBytes, Math.min(dataLength, 256));
        const isPrintable = /^[\x20-\x7E\s]*$/.test(utf8String);
        if (isPrintable && utf8String.length > 0 && dataLength <= 256) {
          output = `UTF-8: ${utf8String}`;
        } else {
          // 显示十六进制
          const hexString = Memory.readByteArray(dataBytes, Math.min(dataLength, 64))
            .map(b => ('0' + (b & 0xFF).toString(16)).slice(-2))
            .join(' ');
          output = dataLength <= 64 ? `Hex: ${hexString}` : `Hex (first 64 bytes): ${hexString}... (total: ${dataLength})`;
        }
      } catch (e) {
        // UTF-8 失败，显示十六进制
        const hexString = Memory.readByteArray(dataBytes, Math.min(dataLength, 64))
          .map(b => ('0' + (b & 0xFF).toString(16)).slice(-2))
          .join(' ');
        output = dataLength <= 64 ? `Hex: ${hexString}` : `Hex (first 64 bytes): ${hexString}... (total: ${dataLength})`;
      }
    }
    // NSNumber 类型
    else if (className === 'NSNumber' || className === '__NSCFNumber') {
      output = objcObj.toString();
    }
    // NSDictionary 类型
    else if (className === 'NSDictionary' || className === '__NSCFDictionary' || className === 'NSMutableDictionary') {
      output = objcObj.toString();
    }
    // NSArray 类型
    else if (className === 'NSArray' || className === '__NSCFArray' || className === 'NSMutableArray') {
      const count = objcObj.count();
      output = `Array[${count}]: ${objcObj.toString()}`;
    }
    // Block 类型
    else if (className === '__NSStackBlock__' || className === '__NSMallocBlock__' || className === '__NSGlobalBlock__') {
      output = objcObj.toString();
    }
    // 其他类型，使用 toString()
    else {
      output = objcObj.toString();
    }
  } catch (e) {
    output = `[Error: ${e}] ${objcObj.toString()}`;
  }
  
  return `${output} (${className})`;
}

// 导出函数（如果支持 module.exports）
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { formatObjCObject };
}

