// Educational port database & simulated scan logic.
// Does NOT perform any real network scanning.

export interface PortInfo {
  port: number;
  service: string;
  protocol: "tcp" | "udp" | "tcp/udp";
  description: string;
  risk: "low" | "medium" | "high";
}

export const COMMON_PORTS: PortInfo[] = [
  { port: 20,    service: "FTP-DATA", protocol: "tcp", description: "File Transfer Protocol (data channel)", risk: "medium" },
  { port: 21,    service: "FTP",      protocol: "tcp", description: "File Transfer Protocol (control). Often unencrypted.", risk: "high" },
  { port: 22,    service: "SSH",      protocol: "tcp", description: "Secure Shell — remote login.", risk: "medium" },
  { port: 23,    service: "TELNET",   protocol: "tcp", description: "Plaintext remote shell. Deprecated.", risk: "high" },
  { port: 25,    service: "SMTP",     protocol: "tcp", description: "Email transfer.", risk: "medium" },
  { port: 53,    service: "DNS",      protocol: "tcp/udp", description: "Domain Name System resolution.", risk: "low" },
  { port: 67,    service: "DHCP",     protocol: "udp", description: "Dynamic Host Configuration Protocol (server).", risk: "low" },
  { port: 68,    service: "DHCP",     protocol: "udp", description: "DHCP client.", risk: "low" },
  { port: 69,    service: "TFTP",     protocol: "udp", description: "Trivial FTP — no auth.", risk: "high" },
  { port: 80,    service: "HTTP",     protocol: "tcp", description: "Web traffic (unencrypted).", risk: "medium" },
  { port: 110,   service: "POP3",     protocol: "tcp", description: "Mail retrieval.", risk: "medium" },
  { port: 111,   service: "RPCBIND",  protocol: "tcp/udp", description: "Sun RPC portmapper.", risk: "high" },
  { port: 123,   service: "NTP",      protocol: "udp", description: "Network Time Protocol.", risk: "low" },
  { port: 135,   service: "MSRPC",    protocol: "tcp", description: "Microsoft RPC.", risk: "high" },
  { port: 139,   service: "NETBIOS",  protocol: "tcp", description: "NetBIOS session service.", risk: "high" },
  { port: 143,   service: "IMAP",     protocol: "tcp", description: "Internet Message Access Protocol.", risk: "medium" },
  { port: 161,   service: "SNMP",     protocol: "udp", description: "Simple Network Management Protocol.", risk: "high" },
  { port: 389,   service: "LDAP",     protocol: "tcp", description: "Directory Access Protocol.", risk: "medium" },
  { port: 443,   service: "HTTPS",    protocol: "tcp", description: "HTTP over TLS — encrypted web.", risk: "low" },
  { port: 445,   service: "SMB",      protocol: "tcp", description: "Windows file sharing. EternalBlue target.", risk: "high" },
  { port: 465,   service: "SMTPS",    protocol: "tcp", description: "SMTP over TLS.", risk: "low" },
  { port: 514,   service: "SYSLOG",   protocol: "udp", description: "System log messages.", risk: "medium" },
  { port: 587,   service: "SMTP",     protocol: "tcp", description: "SMTP submission (auth).", risk: "low" },
  { port: 631,   service: "IPP",      protocol: "tcp", description: "Internet Printing Protocol.", risk: "medium" },
  { port: 993,   service: "IMAPS",    protocol: "tcp", description: "IMAP over TLS.", risk: "low" },
  { port: 995,   service: "POP3S",    protocol: "tcp", description: "POP3 over TLS.", risk: "low" },
  { port: 1433,  service: "MSSQL",    protocol: "tcp", description: "Microsoft SQL Server.", risk: "high" },
  { port: 1521,  service: "ORACLE",   protocol: "tcp", description: "Oracle DB listener.", risk: "high" },
  { port: 2049,  service: "NFS",      protocol: "tcp", description: "Network File System.", risk: "high" },
  { port: 3306,  service: "MYSQL",    protocol: "tcp", description: "MySQL database.", risk: "high" },
  { port: 3389,  service: "RDP",      protocol: "tcp", description: "Remote Desktop. Frequent brute-force target.", risk: "high" },
  { port: 5432,  service: "POSTGRES", protocol: "tcp", description: "PostgreSQL database.", risk: "high" },
  { port: 5900,  service: "VNC",      protocol: "tcp", description: "Virtual Network Computing.", risk: "high" },
  { port: 5985,  service: "WINRM",    protocol: "tcp", description: "Windows Remote Management.", risk: "high" },
  { port: 6379,  service: "REDIS",    protocol: "tcp", description: "Redis key-value store. Often unauth.", risk: "high" },
  { port: 8000,  service: "HTTP-ALT", protocol: "tcp", description: "Alternate HTTP / dev server.", risk: "medium" },
  { port: 8080,  service: "HTTP-PROXY", protocol: "tcp", description: "HTTP proxy / app server.", risk: "medium" },
  { port: 8443,  service: "HTTPS-ALT", protocol: "tcp", description: "Alternate HTTPS.", risk: "low" },
  { port: 9200,  service: "ELASTIC",  protocol: "tcp", description: "Elasticsearch REST. Often unauth.", risk: "high" },
  { port: 27017, service: "MONGODB",  protocol: "tcp", description: "MongoDB. Often misconfigured.", risk: "high" },
];

export type PortState = "open" | "closed" | "filtered";

export interface ScanResult {
  port: number;
  state: PortState;
  service: string;
  protocol: string;
  risk: "low" | "medium" | "high" | "info";
  banner?: string;
}

export type ScanType = "quick" | "common" | "full" | "custom";
export type ScanTechnique = "syn" | "connect" | "udp" | "fin";

export const SCAN_TYPE_INFO: Record<ScanType, { label: string; desc: string; ports: () => number[] }> = {
  quick:  { label: "Quick",   desc: "Top 10 ports",       ports: () => [21, 22, 23, 25, 53, 80, 110, 443, 445, 3389] },
  common: { label: "Common",  desc: "All known services", ports: () => COMMON_PORTS.map(p => p.port) },
  full:   { label: "Full",    desc: "1 - 1024 (well-known)", ports: () => Array.from({ length: 1024 }, (_, i) => i + 1) },
  custom: { label: "Custom",  desc: "User-defined range", ports: () => [] },
};

export const TECHNIQUE_INFO: Record<ScanTechnique, { label: string; flag: string; desc: string }> = {
  syn:     { label: "SYN Stealth",     flag: "-sS", desc: "Half-open. Doesn't complete TCP handshake." },
  connect: { label: "TCP Connect",     flag: "-sT", desc: "Full handshake. No raw socket needed." },
  udp:     { label: "UDP Scan",        flag: "-sU", desc: "Sends UDP packets. Slow but reveals UDP services." },
  fin:     { label: "FIN Scan",        flag: "-sF", desc: "Evades stateless firewalls via FIN flag." },
};

// Deterministic pseudo-random based on host + port (so a host scans consistently).
function seededRand(host: string, port: number): number {
  let h = 0;
  const s = host + ":" + port;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(Math.sin(h)) % 1;
}

const BANNERS: Record<number, string> = {
  21:   "220 ProFTPD 1.3.5 Server (Debian) [::ffff:HOST]",
  22:   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
  23:   "Ubuntu 18.04.5 LTS\\r\\nlogin:",
  25:   "220 mail.example.com ESMTP Postfix",
  80:   "HTTP/1.1 200 OK\\r\\nServer: nginx/1.18.0",
  110:  "+OK Dovecot ready.",
  143:  "* OK [CAPABILITY IMAP4rev1] Dovecot ready.",
  443:  "HTTP/1.1 200 OK\\r\\nServer: nginx/1.18.0 (TLS)",
  445:  "SMB Negotiate Response (Windows 10 Pro 19044)",
  3306: "5.7.36-0ubuntu0.18.04.1",
  3389: "RDP cookie: mstshash=Administrator",
  5432: "PostgreSQL 14.5",
  6379: "+PONG  (NO AUTH REQUIRED)",
  27017:"MongoDB 4.4.10  (auth disabled)",
};

export function simulateScan(host: string, port: number, technique: ScanTechnique): ScanResult {
  const info = COMMON_PORTS.find(p => p.port === port);
  const r = seededRand(host, port);

  let state: PortState;
  if (info) {
    // Known services more likely to appear open.
    if (r < 0.55) state = "open";
    else if (r < 0.85) state = "closed";
    else state = "filtered";
  } else {
    if (r < 0.02) state = "open";
    else if (r < 0.92) state = "closed";
    else state = "filtered";
  }

  if (technique === "udp" && state === "open" && r < 0.4) state = "filtered"; // UDP often ambiguous
  if (technique === "fin" && state === "open" && r < 0.3) state = "filtered";

  return {
    port,
    state,
    service: info?.service ?? "unknown",
    protocol: info?.protocol ?? (technique === "udp" ? "udp" : "tcp"),
    risk: info?.risk ?? "info",
    banner: state === "open" ? BANNERS[port] : undefined,
  };
}

export function parsePortRange(input: string): number[] {
  const ports: number[] = [];
  const seen = new Set<number>();
  for (const part of input.split(",").map(s => s.trim()).filter(Boolean)) {
    if (part.includes("-")) {
      const [a, b] = part.split("-").map(n => parseInt(n, 10));
      if (!isNaN(a) && !isNaN(b) && a <= b) {
        for (let p = a; p <= Math.min(b, 65535); p++) {
          if (p >= 1 && !seen.has(p)) { seen.add(p); ports.push(p); }
        }
      }
    } else {
      const p = parseInt(part, 10);
      if (!isNaN(p) && p >= 1 && p <= 65535 && !seen.has(p)) {
        seen.add(p); ports.push(p);
      }
    }
  }
  return ports;
}
