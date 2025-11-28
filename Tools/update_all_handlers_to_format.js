#!/usr/bin/env node
/**
 * 批量更新所有 handler 文件，统一使用 formatObjCObject 输出日志
 */

const fs = require('fs');
const path = require('path');

const HANDLERS_DIR = path.join(__dirname, '..', '__handlers__');

// 需要替换的模式
const REPLACEMENTS = [
  // 模式1: objcObj.toString() + '（' + objcObj.$className + '）'
  {
    pattern: /log\(['"]👉['"]\s*\+\s*(\w+)\.toString\(\)\s*\+\s*['"]（['"]\s*\+\s*\1\.\$className\s*\+\s*['"]）['"]\)/g,
    replacement: "log('👉 ' + formatObjCObject($1))"
  },
  // 模式2: objcObj.$className +" "+ objcObj.toString()
  {
    pattern: /log\(['"]👈:\s*['"]\s*\+\s*(\w+)\.\$className\s*\+\s*['"]\s*['"]\s*\+\s*\1\.toString\(\)/g,
    replacement: "log('👈 ' + formatObjCObject($1))"
  },
  // 模式3: objcObj.$className +" "+ objcObj.toString() + '\n'
  {
    pattern: /log\(['"]👈:\s*['"]\s*\+\s*(\w+)\.\$className\s*\+\s*['"]\s*['"]\s*\+\s*\1\.toString\(\)\s*\+\s*['"]\\n['"]\)/g,
    replacement: "log('👈 ' + formatObjCObject($1) + '\\n')"
  },
  // 模式4: objcObj.toString() + '（' + objcObj.$className + '）' (无空格)
  {
    pattern: /log\(['"]👉['"]\s*\+\s*(\w+)\.toString\(\)\s*\+\s*['"]（['"]\s*\+\s*\1\.\$className\s*\+\s*['"]）['"]\)/g,
    replacement: "log('👉 ' + formatObjCObject($1))"
  },
];

// 修复 ObjC.Object 为 new ObjC.Object
function fixObjCObjectCreation(content) {
  // 将 ObjC.Object(args[X]) 替换为 new ObjC.Object(args[X])
  return content.replace(/\bObjC\.Object\(/g, 'new ObjC.Object(');
}

// 更新单个文件
function updateFile(filePath) {
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    let modified = false;
    let originalContent = content;

    // 跳过已经使用 formatObjCObject 的文件（如果所有日志都已经使用）
    if (content.includes('formatObjCObject') && 
        !content.match(/\.toString\(\)\s*\+\s*['"]（['"]\s*\+\s*\w+\.\$className/) &&
        !content.match(/\$className\s*\+\s*['"]\s*['"]\s*\+\s*\w+\.toString\(\)/)) {
      return { updated: false, reason: 'already using formatObjCObject' };
    }

    // 应用所有替换模式
    for (const { pattern, replacement } of REPLACEMENTS) {
      const newContent = content.replace(pattern, replacement);
      if (newContent !== content) {
        content = newContent;
        modified = true;
      }
    }

    // 修复 ObjC.Object 创建
    const fixedContent = fixObjCObjectCreation(content);
    if (fixedContent !== content) {
      content = fixedContent;
      modified = true;
    }

    // 如果文件被修改，写回
    if (modified) {
      fs.writeFileSync(filePath, content, 'utf8');
      return { updated: true, reason: 'updated' };
    }

    return { updated: false, reason: 'no changes needed' };
  } catch (error) {
    return { updated: false, reason: `error: ${error.message}` };
  }
}

// 递归查找所有 .js 文件
function findJSFiles(dir) {
  const files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...findJSFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      files.push(fullPath);
    }
  }

  return files;
}

// 主函数
function main() {
  console.log(`📁 扫描目录: ${HANDLERS_DIR}\n`);

  if (!fs.existsSync(HANDLERS_DIR)) {
    console.error(`❌ 目录不存在: ${HANDLERS_DIR}`);
    process.exit(1);
  }

  const jsFiles = findJSFiles(HANDLERS_DIR);
  console.log(`找到 ${jsFiles.length} 个 JS 文件\n`);

  let updatedCount = 0;
  let skippedCount = 0;
  let errorCount = 0;

  for (const filePath of jsFiles) {
    const relativePath = path.relative(path.join(__dirname, '..'), filePath);
    const result = updateFile(filePath);

    if (result.updated) {
      console.log(`✅ ${relativePath}`);
      updatedCount++;
    } else if (result.reason === 'already using formatObjCObject') {
      console.log(`⏭️  ${relativePath} (已使用 formatObjCObject)`);
      skippedCount++;
    } else if (result.reason.startsWith('error')) {
      console.log(`❌ ${relativePath} (${result.reason})`);
      errorCount++;
    } else {
      console.log(`➖ ${relativePath} (无需更新)`);
      skippedCount++;
    }
  }

  console.log(`\n📊 统计:`);
  console.log(`  ✅ 已更新: ${updatedCount}`);
  console.log(`  ⏭️  已跳过: ${skippedCount}`);
  console.log(`  ❌ 错误: ${errorCount}`);
}

main();

