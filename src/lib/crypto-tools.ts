// Educational cryptography implementations.
// NOT for production use.

export function caesar(text: string, shift: number, decrypt = false): string {
  const s = ((decrypt ? -shift : shift) % 26 + 26) % 26;
  return text.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + s) % 26) + base);
  });
}

export function vigenere(text: string, key: string, decrypt = false): string {
  if (!key) return text;
  const k = key.toLowerCase().replace(/[^a-z]/g, "");
  if (!k) return text;
  let ki = 0;
  return text.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= "Z" ? 65 : 97;
    const shift = k.charCodeAt(ki % k.length) - 97;
    ki++;
    const s = decrypt ? -shift : shift;
    return String.fromCharCode(((c.charCodeAt(0) - base + s + 26) % 26) + base);
  });
}

export function atbash(text: string): string {
  return text.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(25 - (c.charCodeAt(0) - base) + base);
  });
}

export function xorCipher(text: string, key: string): string {
  if (!key) return text;
  let out = "";
  for (let i = 0; i < text.length; i++) {
    out += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return out;
}

export function toBase64(text: string): string {
  try { return btoa(unescape(encodeURIComponent(text))); } catch { return ""; }
}
export function fromBase64(text: string): string {
  try { return decodeURIComponent(escape(atob(text))); } catch { return "[invalid base64]"; }
}

export function toBinary(text: string): string {
  return Array.from(text).map(c => c.charCodeAt(0).toString(2).padStart(8, "0")).join(" ");
}
export function fromBinary(text: string): string {
  return text.trim().split(/\s+/).map(b => String.fromCharCode(parseInt(b, 2) || 0)).join("");
}

export function toHex(text: string): string {
  return Array.from(text).map(c => c.charCodeAt(0).toString(16).padStart(2, "0")).join(" ");
}
export function fromHex(text: string): string {
  return text.trim().split(/\s+/).map(h => String.fromCharCode(parseInt(h, 16) || 0)).join("");
}

export function rot13(text: string): string {
  return caesar(text, 13);
}

export function morse(text: string): string {
  const map: Record<string, string> = {
    a:".-",b:"-...",c:"-.-.",d:"-..",e:".",f:"..-.",g:"--.",h:"....",i:"..",j:".---",
    k:"-.-",l:".-..",m:"--",n:"-.",o:"---",p:".--.",q:"--.-",r:".-.",s:"...",t:"-",
    u:"..-",v:"...-",w:".--",x:"-..-",y:"-.--",z:"--..",
    "0":"-----","1":".----","2":"..---","3":"...--","4":"....-",
    "5":".....","6":"-....","7":"--...","8":"---..","9":"----."
  };
  return text.toLowerCase().split("").map(c => c === " " ? "/" : map[c] || "").filter(Boolean).join(" ");
}
export function fromMorse(text: string): string {
  const map: Record<string, string> = {
    ".-":"a","-...":"b","-.-.":"c","-..":"d",".":"e","..-.":"f","--.":"g","....":"h","..":"i",".---":"j",
    "-.-":"k",".-..":"l","--":"m","-.":"n","---":"o",".--.":"p","--.-":"q",".-.":"r","...":"s","-":"t",
    "..-":"u","...-":"v",".--":"w","-..-":"x","-.--":"y","--..":"z",
    "-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",
    ".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"
  };
  return text.split(" ").map(t => t === "/" ? " " : (map[t] || "")).join("");
}

export async function sha256(text: string): Promise<string> {
  const buf = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}
export async function sha1(text: string): Promise<string> {
  const buf = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-1", buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

export function randomKey(len = 16): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(n => chars[n % chars.length]).join("");
}
