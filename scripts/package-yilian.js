#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { ROOT } = require('../lib/engine');
const { version } = require('../package.json');

// Store 模式 ZIP：包只包含声明与 Skill，不依赖第三方压缩库。
function crc32(bytes) { // nosec: ZIP 格式要求 CRC32 校验，不用于密码或安全摘要
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function zip(files) {
  const local = [], central = [];
  let offset = 0;
  for (const [name, content] of files) {
    const filename = Buffer.from(name), data = Buffer.from(content), crc = crc32(data); // nosec: ZIP 格式校验
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(0x800, 6);
    header.writeUInt16LE(33, 12); // 1980-01-01，制品可复现
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(data.length, 18);
    header.writeUInt32LE(data.length, 22);
    header.writeUInt16LE(filename.length, 26);
    local.push(header, filename, data);
    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50, 0);
    record.writeUInt16LE(20, 4);
    header.copy(record, 6, 4, 30);
    record.writeUInt32LE(offset, 42);
    central.push(record, filename);
    offset += header.length + filename.length + data.length;
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
}

function build(output = path.join(ROOT, 'dist/yilian')) {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'plugin/plugin.json'), 'utf8')); // nosec: 仓库内固定清单路径
  manifest.version = version;
  const template = manifest.contributes.mcp_server_templates[0];
  template.command = process.execPath;
  template.args = [path.join(ROOT, 'bin/sourceaudit-mcp.js')];
  const config = { name: template.name, transport: 'stdio', command: template.command, args: template.args, env: {}, enabled: false };
  const files = [
    ['plugin.json', JSON.stringify(manifest, null, 2) + '\n'],
    ['skills/sourceaudit/SKILL.md', fs.readFileSync(path.join(ROOT, 'plugin/skills/sourceaudit/SKILL.md'))]
  ];
  fs.mkdirSync(output, { recursive: true });
  const packagePath = path.join(output, `sourceaudit-yilian-${version}.zip`);
  fs.writeFileSync(packagePath, zip(files));
  const configPath = path.join(output, 'sourceaudit-mcp.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
  return { packagePath, configPath };
}
if (require.main === module) {
  const result = build(process.argv[2] ? path.resolve(process.argv[2]) : undefined);
  console.log(`插件包：${result.packagePath}\nMCP 配置：${result.configPath}\n配置绑定当前 Node 与源码路径；移动目录后重新生成。`);
}
module.exports = { build, zip };
