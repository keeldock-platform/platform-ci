export function parseStrictJson(text, maxBytes = 16 * 1024 * 1024) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error('json-size');
  let index = 0;
  const whitespace = () => { while (index < text.length && /[ \t\r\n]/.test(text[index])) index += 1; };
  const string = () => {
    if (text[index] !== '"') throw new Error('json-string');
    const start = index++;
    while (index < text.length) {
      const character = text[index++];
      if (character === '"') return JSON.parse(text.slice(start, index));
      if (character === '\\') {
        if (index >= text.length) throw new Error('json-escape');
        const escaped = text[index++];
        if (escaped === 'u') {
          const digits = text.slice(index, index + 4);
          if (!/^[0-9A-Fa-f]{4}$/.test(digits)) throw new Error('json-escape');
          index += 4;
        } else if (!'"\\/bfnrt'.includes(escaped)) throw new Error('json-escape');
      } else if (character.charCodeAt(0) < 0x20) throw new Error('json-control');
    }
    throw new Error('json-string');
  };
  const value = (depth = 0) => {
    if (depth > 128) throw new Error('json-depth');
    whitespace();
    const character = text[index];
    if (character === '"') return string();
    if (character === '{') {
      index += 1;
      whitespace();
      const result = Object.create(null);
      const keys = new Set();
      if (text[index] === '}') { index += 1; return result; }
      while (true) {
        whitespace();
        const key = string();
        if (keys.has(key)) throw new Error('duplicate-json-key');
        keys.add(key);
        whitespace();
        if (text[index++] !== ':') throw new Error('json-colon');
        result[key] = value(depth + 1);
        whitespace();
        const delimiter = text[index++];
        if (delimiter === '}') return result;
        if (delimiter !== ',') throw new Error('json-object');
      }
    }
    if (character === '[') {
      index += 1;
      whitespace();
      const result = [];
      if (text[index] === ']') { index += 1; return result; }
      while (true) {
        result.push(value(depth + 1));
        whitespace();
        const delimiter = text[index++];
        if (delimiter === ']') return result;
        if (delimiter !== ',') throw new Error('json-array');
      }
    }
    const match = /^(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)/.exec(text.slice(index));
    if (!match) throw new Error('json-value');
    index += match[0].length;
    return JSON.parse(match[0]);
  };
  const result = value();
  whitespace();
  if (index !== text.length) throw new Error('json-trailing-data');
  return result;
}
