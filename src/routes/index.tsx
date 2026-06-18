import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import {
  caesar, vigenere, atbash, xorCipher, toBase64, fromBase64,
  toBinary, fromBinary, toHex, fromHex, rot13, morse, fromMorse,
  sha256, sha1, randomKey,
} from "@/lib/crypto-tools";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "CryptoLab // Cryptography Toolkit" },
      { name: "description", content: "Interactive cryptography toolkit for learning cyber security: Caesar, Vigenère, XOR, Base64, hashes and more." },
    ],
  }),
  component: CryptoLab,
});

type ToolId =
  | "caesar" | "vigenere" | "atbash" | "rot13" | "xor"
  | "base64" | "binary" | "hex" | "morse" | "sha256" | "sha1";

interface Tool {
  id: ToolId;
  name: string;
  needsKey?: boolean;
  needsShift?: boolean;
  hashOnly?: boolean;
  desc: string;
}

const TOOLS: Tool[] = [
  { id: "caesar",   name: "CAESAR",    needsShift: true, desc: "Shift each letter by N positions." },
  { id: "vigenere", name: "VIGENÈRE",  needsKey: true,   desc: "Polyalphabetic cipher using a keyword." },
  { id: "atbash",   name: "ATBASH",    desc: "Reverse alphabet substitution (A↔Z)." },
  { id: "rot13",    name: "ROT13",     desc: "Caesar cipher with shift 13 (self-inverse)." },
  { id: "xor",      name: "XOR",       needsKey: true,   desc: "Bitwise XOR each char against key." },
  { id: "base64",   name: "BASE64",    desc: "Binary-to-text encoding." },
  { id: "binary",   name: "BINARY",    desc: "Convert text to/from 8-bit binary." },
  { id: "hex",      name: "HEX",       desc: "Convert text to/from hexadecimal." },
  { id: "morse",    name: "MORSE",     desc: "International morse code." },
  { id: "sha256",   name: "SHA-256",   hashOnly: true,   desc: "One-way cryptographic hash." },
  { id: "sha1",     name: "SHA-1",     hashOnly: true,   desc: "Legacy hash (broken — educational)." },
];

function CryptoLab() {
  const [tool, setTool] = useState<ToolId>("caesar");
  const [mode, setMode] = useState<"encrypt" | "decrypt">("encrypt");
  const [input, setInput] = useState("the quick brown fox jumps over the lazy dog");
  const [keyVal, setKeyVal] = useState("secret");
  const [shift, setShift] = useState(3);
  const [output, setOutput] = useState("");
  const [log, setLog] = useState<string[]>([
    "[boot] cryptolab v1.0 initialized",
    "[info] select a cipher and press EXECUTE",
  ]);
  const [booted, setBooted] = useState(false);

  useEffect(() => { setBooted(true); }, []);

  const current = TOOLS.find(t => t.id === tool)!;

  const pushLog = (line: string) => {
    setLog(l => [...l.slice(-30), `[${new Date().toLocaleTimeString()}] ${line}`]);
  };

  const execute = async () => {
    const decrypt = mode === "decrypt";
    let result = "";
    try {
      switch (tool) {
        case "caesar":   result = caesar(input, shift, decrypt); break;
        case "vigenere": result = vigenere(input, keyVal, decrypt); break;
        case "atbash":   result = atbash(input); break;
        case "rot13":    result = rot13(input); break;
        case "xor":      result = xorCipher(input, keyVal); break;
        case "base64":   result = decrypt ? fromBase64(input) : toBase64(input); break;
        case "binary":   result = decrypt ? fromBinary(input) : toBinary(input); break;
        case "hex":      result = decrypt ? fromHex(input) : toHex(input); break;
        case "morse":    result = decrypt ? fromMorse(input) : morse(input); break;
        case "sha256":   result = await sha256(input); break;
        case "sha1":     result = await sha1(input); break;
      }
      setOutput(result);
      pushLog(`${current.name} ${current.hashOnly ? "HASH" : mode.toUpperCase()} → ${result.length} chars`);
    } catch (e) {
      pushLog(`ERROR: ${(e as Error).message}`);
    }
  };

  const swap = () => {
    setInput(output);
    setOutput("");
    pushLog("output → input");
  };

  const clearAll = () => {
    setInput(""); setOutput("");
    pushLog("cleared buffers");
  };

  const copyOut = async () => {
    if (!output) return;
    await navigator.clipboard.writeText(output);
    pushLog("copied output to clipboard");
  };

  const genKey = () => {
    const k = randomKey(16);
    setKeyVal(k);
    pushLog(`generated random key (${k.length} chars)`);
  };

  return (
    <div className="min-h-screen text-foreground relative overflow-hidden">
      {/* scanline overlay */}
      <div className="pointer-events-none fixed inset-0 z-50 opacity-[0.06]"
           style={{ background: "repeating-linear-gradient(180deg, var(--terminal) 0 1px, transparent 1px 4px)" }} />

      <div className="max-w-6xl mx-auto p-4 md:p-8 relative z-10">
        {/* Header */}
        <header className="border border-terminal/40 rounded-md p-4 mb-6 bg-card/60 backdrop-blur">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <h1 className={`text-2xl md:text-3xl font-bold text-glow tracking-widest ${booted ? "blink-cursor" : ""}`}>
                ▮ CRYPTO_LAB
              </h1>
              <p className="text-xs text-terminal-dim mt-1 tracking-wider">
                &gt; CYBER-SECURITY // CRYPTOGRAPHY TOOLKIT // v1.0
              </p>
            </div>
            <div className="text-xs text-terminal-dim text-right">
              <div>STATUS: <span className="text-terminal text-glow">ONLINE</span></div>
              <div>SESSION: {new Date().toISOString().slice(0, 10)}</div>
            </div>
          </div>
        </header>

        {/* Tool grid */}
        <section className="mb-6">
          <h2 className="text-xs text-terminal-dim mb-2 tracking-widest">// SELECT CIPHER</h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2">
            {TOOLS.map(t => (
              <button
                key={t.id}
                onClick={() => { setTool(t.id); pushLog(`loaded module: ${t.name}`); }}
                className={`btn-terminal text-xs ${tool === t.id ? "bg-terminal/30 shadow-glow" : ""}`}
              >
                {t.name}
              </button>
            ))}
          </div>
          <p className="text-xs text-terminal-dim mt-2 italic">// {current.desc}</p>
        </section>

        {/* Controls */}
        <section className="grid md:grid-cols-2 gap-4 mb-4">
          <div className="border border-terminal/40 rounded-md p-4 bg-card/60">
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-terminal-dim tracking-widest">INPUT &gt;</label>
              <div className="text-xs text-terminal-dim">{input.length} chars</div>
            </div>
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              rows={8}
              spellCheck={false}
              className="w-full bg-background border border-terminal/30 rounded p-3 text-terminal font-mono text-sm focus:outline-none focus:border-terminal focus:shadow-glow resize-none"
              placeholder="// type plaintext or ciphertext here..."
            />
          </div>

          <div className="border border-terminal/40 rounded-md p-4 bg-card/60">
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-terminal-dim tracking-widest">OUTPUT &gt;</label>
              <div className="text-xs text-terminal-dim">{output.length} chars</div>
            </div>
            <textarea
              value={output}
              readOnly
              rows={8}
              spellCheck={false}
              className="w-full bg-background border border-terminal/30 rounded p-3 text-terminal-bright font-mono text-sm text-glow resize-none"
              placeholder="// result will appear here..."
            />
          </div>
        </section>

        {/* Parameters */}
        <section className="border border-terminal/40 rounded-md p-4 bg-card/60 mb-4">
          <h2 className="text-xs text-terminal-dim mb-3 tracking-widest">// PARAMETERS</h2>
          <div className="flex flex-wrap gap-4 items-end">
            {!current.hashOnly && (
              <div className="flex gap-2">
                <button
                  onClick={() => setMode("encrypt")}
                  className={`btn-terminal text-xs ${mode === "encrypt" ? "bg-terminal/30 shadow-glow" : ""}`}
                >ENCRYPT</button>
                <button
                  onClick={() => setMode("decrypt")}
                  className={`btn-terminal text-xs ${mode === "decrypt" ? "bg-terminal/30 shadow-glow" : ""}`}
                >DECRYPT</button>
              </div>
            )}

            {current.needsShift && (
              <div>
                <label className="block text-xs text-terminal-dim mb-1">SHIFT [{shift}]</label>
                <input
                  type="range" min={1} max={25} value={shift}
                  onChange={e => setShift(parseInt(e.target.value))}
                  className="w-40 accent-terminal"
                />
              </div>
            )}

            {current.needsKey && (
              <div className="flex-1 min-w-[220px]">
                <label className="block text-xs text-terminal-dim mb-1">KEY</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={keyVal}
                    onChange={e => setKeyVal(e.target.value)}
                    className="flex-1 bg-background border border-terminal/30 rounded px-3 py-2 text-terminal font-mono text-sm focus:outline-none focus:border-terminal focus:shadow-glow"
                    placeholder="secret_key"
                  />
                  <button onClick={genKey} className="btn-terminal text-xs">GEN</button>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Action buttons */}
        <section className="flex flex-wrap gap-2 mb-6">
          <button onClick={execute} className="btn-terminal shadow-glow font-bold">
            ▶ EXECUTE
          </button>
          <button onClick={swap} className="btn-terminal">⇅ SWAP</button>
          <button onClick={copyOut} className="btn-terminal">⎘ COPY</button>
          <button onClick={clearAll} className="btn-terminal">✕ CLEAR</button>
        </section>

        {/* Log */}
        <section className="border border-terminal/40 rounded-md bg-background/80 p-4">
          <h2 className="text-xs text-terminal-dim mb-2 tracking-widest">// SYSTEM LOG</h2>
          <div className="font-mono text-xs space-y-0.5 max-h-48 overflow-y-auto">
            {log.map((l, i) => (
              <div key={i} className="text-terminal-dim">
                <span className="text-terminal">$</span> {l}
              </div>
            ))}
          </div>
        </section>

        <footer className="text-center text-xs text-terminal-dim mt-6 tracking-widest">
          // EDUCATIONAL USE ONLY // DO NOT USE FOR REAL SECURITY //
        </footer>
      </div>
    </div>
  );
}
