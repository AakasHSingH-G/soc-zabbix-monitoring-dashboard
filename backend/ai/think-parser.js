function stripReasoningTags(raw) {
  if (typeof raw !== 'string') return '';
  let text = raw.trim();
  if (!text) return '';
  const start = text.indexOf('<think>');
  if (start === -1) return text;

  const end = text.indexOf('</think>', start);
  if (end >= 0) {
    return text.slice(end + '</think>'.length).trim();
  }

  const afterStart = text.slice(start + '<think>'.length);
  const lineBreak = afterStart.search(/\r?\n\s*\r?\n|\r?\n/);
  if (lineBreak >= 0) return afterStart.slice(lineBreak + 1).trim();

  return '';
}

function extractJsonResponse(raw) {
  if (typeof raw !== 'string') return null;
  let text = stripReasoningTags(raw).trim();
  if (!text) return null;

  const thinkingEnd = text.lastIndexOf('</think>');
  if (thinkingEnd >= 0) text = text.slice(thinkingEnd + '</think>'.length).trim();
  else if (text.includes('<think>')) return null;

  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') inString = true;
    else if (character === '{') {
      if (depth === 0) start = index;
      depth += 1;
    } else if (character === '}') {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        try { return JSON.parse(text.slice(start, index + 1)); } catch { return null; }
      }
    }
  }
  return null;
}

module.exports = { extractJsonResponse, stripReasoningTags };
