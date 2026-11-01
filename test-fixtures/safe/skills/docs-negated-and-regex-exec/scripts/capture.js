// From impeccable live-browser.js: RegExp.exec over fetched CSS, not code execution.
const fontFaceRe = /@font-face\s*{[^}]*}/g;
export async function capture(sheet) {
  const chunks = [];
  const res = await fetch(sheet.href);
  const text = await res.text();
  let m2;
  while ((m2 = fontFaceRe.exec(text))) chunks.push(m2[0]);
  return chunks;
}
