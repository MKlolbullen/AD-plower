// Thin typed wrapper around the Wails bindings for gui.App. Using
// `window.go.gui.App.<Method>` means we don't depend on the auto-generated
// ./wailsjs files at type-check time — the runtime bridge resolves the same
// way as the generated stubs.

export type TargetInput = {
  domain?: string;
  target?: string;
  username?: string;
  password?: string;
  ntHash?: string;
  dc?: string;
  dnsServer?: string;
  workspace?: string;
  bhNeo4jUri?: string;
  bhNeo4jUser?: string;
  bhNeo4jPass?: string;
  bhCeEnabled?: boolean;
  threads?: number;
};

export type ConfigSnapshot = {
  domain: string;
  target: string;
  username: string;
  password: string;
  ntHash: string;
  dc: string;
  dnsServer: string;
  workspace: string;
  bhNeo4jUri: string;
  bhNeo4jUser: string;
  bhCeEnabled: boolean;
  threads: number;
};

export type TrustInfo = {
  name: string;
  direction: number;
  type: number;
  attrs: number;
};

export type SPNInfo = { user: string; spn: string };

export type SMBHost = {
  host: string;
  signing_required: boolean;
  null_session: boolean;
  shares: string[];
  os: string;
  domain: string;
};

export type Cred = { user: string; password: string; hash: string; source: string };

export type ADCSEntry = { ca_name: string; dns_name: string; templates: string[] };

export type VulnFinding = {
  name: string;
  target: string;
  severity: string;
  confidence: string;
  notes: string;
};

export type ReconResults = {
  domain: string;
  dcs: string[];
  users: string[];
  groups: string[];
  computers: string[];
  trusts: TrustInfo[];
  spns: SPNInfo[];
  smb_hosts: SMBHost[];
  asrep_hashes: Record<string, string>;
  tgs_hashes: Record<string, string>;
  valid_creds: Cred[];
  adcs_cas: ADCSEntry[];
  vulns: VulnFinding[];
  modules: Record<string, unknown>;
  updated_at: string;
};

export type LogEvent = { time: string; scope: string; msg: string };

type App = {
  SetTarget(in_: TargetInput): Promise<ConfigSnapshot>;
  GetConfig(): Promise<ConfigSnapshot>;
  FirstDC(): Promise<string>;
  RunUnauthRecon(): Promise<unknown>;
  RunDNSRecon(): Promise<unknown>;
  RunLDAPEnum(dc: string): Promise<unknown>;
  RunSMBEnum(args: { host: string; authenticated: boolean }): Promise<unknown>;
  RunRIDBrute(args: { dc: string; start: number; end: number }): Promise<unknown>;
  RunASREPRoast(args: { dc: string; users: string[] }): Promise<unknown>;
  RunKerberoast(dc: string): Promise<unknown>;
  RunSpray(args: {
    dc: string;
    users: string[];
    passwords: string[];
    userFile: string;
    passwordFile: string;
    delaySeconds: number;
    stopOnSuccess: boolean;
  }): Promise<unknown>;
  RunADCSEnum(dc: string): Promise<unknown>;
  RunTrusts(dc: string): Promise<unknown>;
  RunVulns(dc: string): Promise<unknown>;
  IngestBloodHound(): Promise<void>;
  GetResults(): Promise<ReconResults>;
};

type WailsRuntime = {
  EventsOn(event: string, cb: (data: any) => void): () => void;
  EventsOff(event: string): void;
};

declare global {
  interface Window {
    go?: { gui: { App: App } };
    runtime?: WailsRuntime;
  }
}

// In the rare case that the Wails runtime is not attached (e.g. the assets
// are loaded in a plain browser for development) we fall back to a shim that
// throws a visible error instead of silently doing nothing.
function bridge(): App {
  if (!window.go?.gui?.App) {
    const stub = new Proxy(
      {},
      {
        get() {
          return async () => {
            throw new Error(
              "Wails runtime is not available — build with `wails build` or start with `wails dev`.",
            );
          };
        },
      },
    );
    return stub as App;
  }
  return window.go.gui.App;
}

export const api = {
  setTarget: (t: TargetInput) => bridge().SetTarget(t),
  getConfig: () => bridge().GetConfig(),
  firstDC: () => bridge().FirstDC(),
  runUnauthRecon: () => bridge().RunUnauthRecon(),
  runDNS: () => bridge().RunDNSRecon(),
  runLDAP: (dc: string) => bridge().RunLDAPEnum(dc),
  runSMB: (host: string, authenticated: boolean) =>
    bridge().RunSMBEnum({ host, authenticated }),
  runRID: (dc: string, start: number, end: number) =>
    bridge().RunRIDBrute({ dc, start, end }),
  runASREP: (dc: string, users: string[]) =>
    bridge().RunASREPRoast({ dc, users }),
  runKerberoast: (dc: string) => bridge().RunKerberoast(dc),
  runSpray: (args: {
    dc: string;
    users: string[];
    passwords: string[];
    userFile: string;
    passwordFile: string;
    delaySeconds: number;
    stopOnSuccess: boolean;
  }) => bridge().RunSpray(args),
  runADCS: (dc: string) => bridge().RunADCSEnum(dc),
  runTrusts: (dc: string) => bridge().RunTrusts(dc),
  runVulns: (dc: string) => bridge().RunVulns(dc),
  ingestBloodHound: () => bridge().IngestBloodHound(),
  getResults: () => bridge().GetResults(),
  onEvent<T = any>(name: string, cb: (data: T) => void): () => void {
    if (!window.runtime) return () => {};
    return window.runtime.EventsOn(name, cb);
  },
};
