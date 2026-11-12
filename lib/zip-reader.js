'use strict';
const fs = require('node:fs/promises');
const { promisify } = require('node:util');
const inflate = promisify(require('node:zlib').inflateRaw);

// 先枚举中央目录。调用方选择条目后才读取与解压其内容。
async function* zipEntries(filename) {
  const file = await fs.open(filename, 'r');
  async function read(offset, length) {
    const buffer = Buffer.alloc(length);
    let position = 0;
    while (position < length) {
      const { bytesRead } = await file.read(buffer, position, length - position, offset + position);
      if (!bytesRead) throw new Error('ZIP 文件内容不完整');
      position += bytesRead;
    }
    return buffer;
  }
  try {
    const size = (await file.stat()).size;
    const tail = await read(Math.max(0, size - 65557), Math.min(size, 65557));
    let end = tail.length - 22;
    while (end >= 0 && (tail.readUInt32LE(end) !== 0x06054b50 || end + 22 + tail.readUInt16LE(end + 20) !== tail.length)) end--;
    if (end < 0) throw new Error('不是有效的 ZIP 文件');
    const count = tail.readUInt16LE(end + 10);
    const centralSize = tail.readUInt32LE(end + 12);
    const centralOffset = tail.readUInt32LE(end + 16);
    if (count === 0xffff || centralOffset === 0xffffffff || centralSize === 0xffffffff) throw new Error('不支持 ZIP64');
    const central = await read(centralOffset, centralSize);
    let offset = 0;
    for (let index = 0; index < count; index++) {
      if (central.readUInt32LE(offset) !== 0x02014b50) throw new Error('ZIP 中央目录不完整');
      const flags = central.readUInt16LE(offset + 8), method = central.readUInt16LE(offset + 10);
      const compressed = central.readUInt32LE(offset + 20), size = central.readUInt32LE(offset + 24);
      const nameLength = central.readUInt16LE(offset + 28);
      const localOffset = central.readUInt32LE(offset + 42);
      const name = central.subarray(offset + 46, offset + 46 + nameLength).toString('utf8').replace(/\\/g, '/');
      offset += 46 + nameLength + central.readUInt16LE(offset + 30) + central.readUInt16LE(offset + 32);
      if (name.endsWith('/')) continue;
      yield {
        name, size, compressed,
        async read() {
          if (flags & 1) throw new Error('不支持加密 ZIP 条目');
          if (![0, 8].includes(method)) throw new Error(`不支持 ZIP 压缩方式 ${method}`);
          const header = await read(localOffset, 30);
          if (header.readUInt32LE(0) !== 0x04034b50) throw new Error('ZIP 条目头无效');
          const data = await read(localOffset + 30 + header.readUInt16LE(26) + header.readUInt16LE(28), compressed);
          return method === 0 ? data : inflate(data);
        }
      };
    }
  } finally { await file.close(); }
}

module.exports = { zipEntries };
