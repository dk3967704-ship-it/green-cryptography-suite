import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  COMMON_PORTS, SCAN_TYPE_INFO, TECHNIQUE_INFO,
  simulateScan, parsePortRange,
  type ScanType, type ScanTechnique, type ScanResult,
} from "@/lib/port-scanner";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "PortScope // Educational Port Scanner" },
      { name: "description", content: "GUI-friendly educational port-scanning toolkit for learning cyber security. Simulates Nmap-style scans, services, banners and risk levels." },
    ],
  }),
  component: PortScope,
});

function PortScope() {
  const [host, setHost] = useState("192.168.1.1");
  const [scanType, setScanType] = useState<ScanType>("quick");
  const [technique, setTechnique] = useState<ScanTechnique>("syn");
  const [customPorts, setCustomPorts] = useState("1-100, 443, 8080");
  const [timeout_, setTimeout_] = useState(150);

  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [log, setLog] = useState<string[]>([
    "PortScope ready. Configure target and press START SCAN.",
  ]);
  const [filter, setFilter] = useState<"all" | "open" | "closed" | "filtered">("open");
  const stopRef = useRef(false);

  const portsToScan = useMemo(() => {
    return scanType === "custom" ? parsePortRange(customPorts) : SCAN_TYPE_INFO[scanType].ports();
  }, [scanType, customPorts]);

  const pushLog = (line: string) => {
    setLog(l => [...l.slice(-100), `[${new Date().toLocaleTimeString()}] ${line}`]);
  };

  const startScan = async () => {
    if (!host.trim()) { pushLog("ERROR: target host is empty"); return; }
    if (portsToScan.length === 0) { pushLog("ERROR: no ports to scan"); return; }

    stopRef.current = false;
    setScanning(true);
    setResults([]);
    setProgress(0);
    pushLog(`Starting ${TECHNIQUE_INFO[technique].flag} scan against ${host}`);
    pushLog(`Scanning ${portsToScan.length} port(s) — timeout ${timeout_}ms`);

    const found: ScanResult[] = [];
    for (let i = 0; i < portsToScan.length; i++) {
      if (stopRef.current) { pushLog("Scan aborted by user."); break; }
      const port = portsToScan[i];
      // simulate latency proportional to timeout
      await new Promise(r => setTimeout(r, Math.max(8, timeout_ / 8)));
      const res = simulateScan(host, port, technique);
      found.push(res);
      if (res.state === "open") {
        pushLog(`OPEN  ${String(port).padStart(5)}/${res.protocol.padEnd(7)} ${res.service}${res.banner ? "  — " + res.banner.slice(0, 50) : ""}`);
      }
      setProgress(Math.round(((i + 1) / portsToScan.length) * 100));
      if ((i + 1) % 25 === 0 || i === portsToScan.length - 1) {
        setResults([...found]);
      }
    }
    setResults(found);
    setScanning(false);
    const openCount = found.filter(r => r.state === "open").length;
    pushLog(`Scan complete. ${openCount} open port(s) of ${found.length} scanned.`);
  };

  const stopScan = () => { stopRef.current = true; };
  const clearAll = () => { setResults([]); setProgress(0); setLog(["Cleared. Ready for new scan."]); };

  const exportJSON = () => {
    const data = { host, technique, scannedAt: new Date().toISOString(), results };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `portscope-${host.replace(/[^\w.-]/g, "_")}.json`;
    a.click();
    URL.revokeObjectURL(url);
    pushLog("Results exported as JSON.");
  };

  const filtered = results.filter(r => filter === "all" || r.state === filter);
  const openCount = results.filter(r => r.state === "open").length;
  const closedCount = results.filter(r => r.state === "closed").length;
  const filteredCount = results.filter(r => r.state === "filtered").length;

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="bg-gradient-to-r from-brand-dark to-brand text-white shadow-lg">
        <div className="max-w-7xl mx-auto px-4 md:px-8 py-5 flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-white/15 backdrop-blur flex items-center justify-center font-mono font-bold text-lg">
              ::
            </div>
            <div>
              <h1 className="text-xl md:text-2xl font-bold tracking-tight">PortScope</h1>
              <p className="text-xs text-white/70 font-mono">Educational Port-Scanning Toolkit</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="chip bg-white/15 text-white">v1.0</span>
            <span className="chip bg-white/15 text-white">SIMULATION MODE</span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 md:px-8 py-6 space-y-6">
        {/* Banner notice */}
        <div className="bg-accent border border-brand/30 rounded-lg p-4 text-sm">
          <strong className="text-brand-dark">For learning only.</strong>{" "}
          <span className="text-foreground/80">
            This tool simulates port-scanning behavior to teach concepts (services, banners, scan techniques). It performs no real network traffic. Only scan systems you own or have written permission to test.
          </span>
        </div>

        {/* Configuration */}
        <section className="bg-card rounded-xl shadow-card border border-border p-5 md:p-6">
          <h2 className="text-sm font-semibold text-brand-dark uppercase tracking-wider mb-4">Scan Configuration</h2>

          <div className="grid md:grid-cols-2 gap-5">
            <div>
              <label className="block text-xs font-semibold text-muted-foreground mb-1.5">TARGET HOST / IP</label>
              <input
                type="text" value={host}
                onChange={e => setHost(e.target.value)}
                disabled={scanning}
                placeholder="192.168.1.1 or example.com"
                className="w-full px-4 py-2.5 border border-border rounded-lg bg-input/40 font-mono text-sm focus:outline-none focus:border-brand focus:shadow-glow transition"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-muted-foreground mb-1.5">
                TIMEOUT PER PORT ({timeout_}ms)
              </label>
              <input
                type="range" min={50} max={500} step={25}
                value={timeout_}
                onChange={e => setTimeout_(parseInt(e.target.value))}
                disabled={scanning}
                className="w-full accent-brand"
              />
            </div>
          </div>

          <div className="mt-5">
            <label className="block text-xs font-semibold text-muted-foreground mb-2">SCAN PROFILE</label>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {(Object.keys(SCAN_TYPE_INFO) as ScanType[]).map(t => (
                <button
                  key={t}
                  disabled={scanning}
                  onClick={() => setScanType(t)}
                  className={`p-3 rounded-lg border-2 text-left transition ${
                    scanType === t
                      ? "border-brand bg-brand/10 shadow-glow"
                      : "border-border bg-card hover:border-brand/50"
                  }`}
                >
                  <div className="font-semibold text-sm text-brand-dark">{SCAN_TYPE_INFO[t].label}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">{SCAN_TYPE_INFO[t].desc}</div>
                </button>
              ))}
            </div>
          </div>

          {scanType === "custom" && (
            <div className="mt-4">
              <label className="block text-xs font-semibold text-muted-foreground mb-1.5">PORT RANGE</label>
              <input
                type="text" value={customPorts}
                onChange={e => setCustomPorts(e.target.value)}
                disabled={scanning}
                placeholder="e.g. 1-1024, 3306, 8000-8100"
                className="w-full px-4 py-2.5 border border-border rounded-lg bg-input/40 font-mono text-sm focus:outline-none focus:border-brand"
              />
            </div>
          )}

          <div className="mt-5">
            <label className="block text-xs font-semibold text-muted-foreground mb-2">SCAN TECHNIQUE</label>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {(Object.keys(TECHNIQUE_INFO) as ScanTechnique[]).map(t => (
                <button
                  key={t}
                  disabled={scanning}
                  onClick={() => setTechnique(t)}
                  className={`p-3 rounded-lg border-2 text-left transition ${
                    technique === t
                      ? "border-brand bg-brand/10 shadow-glow"
                      : "border-border bg-card hover:border-brand/50"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="font-semibold text-sm text-brand-dark">{TECHNIQUE_INFO[t].label}</div>
                    <code className="text-[10px] font-mono bg-secondary px-1.5 py-0.5 rounded text-brand-dark">{TECHNIQUE_INFO[t].flag}</code>
                  </div>
                  <div className="text-xs text-muted-foreground mt-0.5">{TECHNIQUE_INFO[t].desc}</div>
                </button>
              ))}
            </div>
          </div>

          <div className="mt-6 flex flex-wrap items-center gap-3">
            {!scanning ? (
              <button onClick={startScan} className="btn-primary">▶ START SCAN ({portsToScan.length} ports)</button>
            ) : (
              <button onClick={stopScan} className="btn-primary bg-gradient-to-r from-danger to-destructive">■ STOP SCAN</button>
            )}
            <button onClick={clearAll} disabled={scanning} className="btn-outline">CLEAR</button>
            <button onClick={exportJSON} disabled={scanning || results.length === 0} className="btn-outline">↓ EXPORT JSON</button>
            <code className="ml-auto text-xs font-mono bg-secondary px-3 py-2 rounded-md text-brand-dark hidden sm:block">
              nmap {TECHNIQUE_INFO[technique].flag} -p {scanType === "custom" ? customPorts.replace(/\s/g, "") : (scanType === "quick" ? "quick" : scanType)} {host || "<host>"}
            </code>
          </div>
        </section>

        {/* Progress */}
        {(scanning || progress > 0) && (
          <section className="bg-card rounded-xl shadow-card border border-border p-5">
            <div className="flex justify-between items-center mb-2">
              <span className="text-sm font-semibold text-brand-dark">{scanning ? "Scanning…" : "Done"}</span>
              <span className="text-sm font-mono text-muted-foreground">{progress}%</span>
            </div>
            <div className="h-2.5 bg-secondary rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-brand to-brand-dark transition-all duration-150"
                style={{ width: `${progress}%` }}
              />
            </div>
          </section>
        )}

        {/* Results & log */}
        <div className="grid lg:grid-cols-3 gap-6">
          <section className="lg:col-span-2 bg-card rounded-xl shadow-card border border-border overflow-hidden">
            <div className="px-5 py-4 border-b border-border flex items-center justify-between flex-wrap gap-2">
              <h2 className="text-sm font-semibold text-brand-dark uppercase tracking-wider">Results</h2>
              <div className="flex gap-2 text-xs">
                {(["all", "open", "closed", "filtered"] as const).map(f => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={`px-3 py-1 rounded-full font-semibold transition ${
                      filter === f ? "bg-brand text-white" : "bg-secondary text-brand-dark hover:bg-brand/15"
                    }`}
                  >
                    {f.toUpperCase()}
                    {f === "open" && ` (${openCount})`}
                    {f === "closed" && ` (${closedCount})`}
                    {f === "filtered" && ` (${filteredCount})`}
                  </button>
                ))}
              </div>
            </div>
            <div className="overflow-x-auto max-h-[420px] overflow-y-auto">
              {filtered.length === 0 ? (
                <div className="p-10 text-center text-muted-foreground text-sm">
                  {results.length === 0 ? "No scan run yet." : "No results match this filter."}
                </div>
              ) : (
                <table className="w-full text-sm">
                  <thead className="bg-secondary sticky top-0 text-xs uppercase tracking-wider text-brand-dark">
                    <tr>
                      <th className="text-left px-4 py-2.5">Port</th>
                      <th className="text-left px-4 py-2.5">State</th>
                      <th className="text-left px-4 py-2.5">Service</th>
                      <th className="text-left px-4 py-2.5 hidden md:table-cell">Risk</th>
                      <th className="text-left px-4 py-2.5 hidden lg:table-cell">Banner</th>
                    </tr>
                  </thead>
                  <tbody className="font-mono">
                    {filtered.map(r => (
                      <tr key={r.port} className="border-t border-border hover:bg-secondary/50">
                        <td className="px-4 py-2 font-semibold text-brand-dark">
                          {r.port}/<span className="text-muted-foreground text-xs">{r.protocol}</span>
                        </td>
                        <td className="px-4 py-2">
                          <span className={`chip ${
                            r.state === "open" ? "bg-success/15 text-success" :
                            r.state === "closed" ? "bg-muted text-muted-foreground" :
                            "bg-warning/20 text-warning"
                          }`}>
                            ● {r.state}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-foreground">{r.service}</td>
                        <td className="px-4 py-2 hidden md:table-cell">
                          {r.risk !== "info" && (
                            <span className={`chip ${
                              r.risk === "high" ? "bg-danger/15 text-danger" :
                              r.risk === "medium" ? "bg-warning/20 text-warning" :
                              "bg-success/15 text-success"
                            }`}>{r.risk}</span>
                          )}
                        </td>
                        <td className="px-4 py-2 hidden lg:table-cell text-xs text-muted-foreground truncate max-w-[260px]">
                          {r.banner || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </section>

          <section className="bg-brand-dark text-white rounded-xl shadow-card overflow-hidden flex flex-col">
            <div className="px-5 py-4 border-b border-white/10 flex items-center justify-between">
              <h2 className="text-sm font-semibold uppercase tracking-wider">Scan Log</h2>
              <span className="chip bg-white/10 text-white/80">{log.length}</span>
            </div>
            <div className="p-4 font-mono text-xs space-y-1 overflow-y-auto max-h-[420px] flex-1">
              {log.map((l, i) => (
                <div key={i} className="text-white/85 leading-relaxed">
                  <span className="text-white/40">$</span> {l}
                </div>
              ))}
            </div>
          </section>
        </div>

        {/* Port reference */}
        <section className="bg-card rounded-xl shadow-card border border-border p-5 md:p-6">
          <h2 className="text-sm font-semibold text-brand-dark uppercase tracking-wider mb-3">
            Common Port Reference ({COMMON_PORTS.length})
          </h2>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-72 overflow-y-auto pr-2">
            {COMMON_PORTS.map(p => (
              <div key={p.port} className="flex items-start gap-3 p-2.5 rounded-lg bg-secondary/50 border border-border">
                <div className="font-mono font-bold text-brand-dark w-14 shrink-0">{p.port}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-sm">{p.service}</span>
                    <span className={`chip ${
                      p.risk === "high" ? "bg-danger/15 text-danger" :
                      p.risk === "medium" ? "bg-warning/20 text-warning" :
                      "bg-success/15 text-success"
                    }`}>{p.risk}</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5 leading-snug">{p.description}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        <footer className="text-center text-xs text-muted-foreground py-4">
          PortScope · Cyber-Security learning project · Simulation only — no packets sent.
        </footer>
      </main>
    </div>
  );
}

// keep eslint quiet about unused-but-needed effect placeholder if added later
useEffect;
