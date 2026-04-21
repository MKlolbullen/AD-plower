<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import { api, type ConfigSnapshot, type ReconResults } from "../lib/api";

  export let cfg: ConfigSnapshot | null;
  export let results: ReconResults | null;

  const dispatch = createEventDispatcher<{ updated: void }>();

  type ModuleId =
    | "unauth"
    | "dns"
    | "ldap"
    | "smb"
    | "rid"
    | "trusts"
    | "asrep"
    | "kerberoast"
    | "spray"
    | "adcs"
    | "vulns"
    | "ingest";

  // Which module is running right now — only one at a time to keep the
  // log panel coherent.
  let running: ModuleId | null = null;
  let lastOutput: { id: ModuleId; data: unknown } | null = null;
  let lastError: string = "";

  // Per-module form state
  let ridStart = 500;
  let ridEnd = 2000;
  let smbAuthenticated = false;
  let asrepUsers = "";
  let sprayUsers = "";
  let sprayPasswords = "";
  let sprayUserFile = "";
  let sprayPasswordFile = "";
  let sprayDelay = 15;
  let sprayStopOnSuccess = true;

  async function run(id: ModuleId, runner: () => Promise<unknown>) {
    running = id;
    lastError = "";
    try {
      const out = await runner();
      lastOutput = { id, data: out };
      dispatch("updated");
    } catch (e) {
      lastError = String(e);
    } finally {
      running = null;
    }
  }

  async function runASREP() {
    const list = asrepUsers
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    await run("asrep", () => api.runASREP("", list));
  }

  async function runSpray() {
    await run("spray", () =>
      api.runSpray({
        dc: "",
        users: sprayUsers
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        passwords: sprayPasswords
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        userFile: sprayUserFile,
        passwordFile: sprayPasswordFile,
        delaySeconds: sprayDelay,
        stopOnSuccess: sprayStopOnSuccess,
      }),
    );
  }

  $: canAuthed = Boolean(cfg?.username);
</script>

<div class="card">
  <h2>Zero-credential sweep</h2>
  <div class="row">
    <button
      disabled={running !== null || !cfg?.domain}
      on:click={() => run("unauth", api.runUnauthRecon)}
    >
      {running === "unauth" ? "Running…" : "Run unauth recon"}
    </button>
    <button
      disabled={running !== null || !cfg?.domain}
      on:click={() => run("dns", api.runDNS)}
    >
      {running === "dns" ? "Running…" : "DNS SRV only"}
    </button>
    <button
      disabled={running !== null || !results?.dcs?.length}
      on:click={() => run("ldap", () => api.runLDAP(""))}
    >
      {running === "ldap" ? "Running…" : "LDAP enum"}
    </button>
  </div>
</div>

<div class="card">
  <h2>SMB</h2>
  <div class="row">
    <label style="display:flex; gap:0.5rem; align-items:center; flex:0 0 auto;">
      <input type="checkbox" bind:checked={smbAuthenticated} disabled={!canAuthed} />
      <span class="kbd">Authenticated</span>
    </label>
    <button
      disabled={running !== null || !results?.dcs?.length}
      on:click={() =>
        run("smb", () => api.runSMB("", smbAuthenticated))}
    >
      {running === "smb" ? "Running…" : "SMB enum"}
    </button>
  </div>
</div>

<div class="card">
  <h2>LSA RID bruteforce</h2>
  <div class="row">
    <div>
      <label>Start RID</label>
      <input type="number" bind:value={ridStart} />
    </div>
    <div>
      <label>End RID</label>
      <input type="number" bind:value={ridEnd} />
    </div>
    <button
      disabled={running !== null || !results?.dcs?.length}
      on:click={() => run("rid", () => api.runRID("", ridStart, ridEnd))}
    >
      {running === "rid" ? "Running…" : "RID cycle"}
    </button>
  </div>
</div>

<div class="card">
  <h2>Kerberos</h2>
  <div class="grid cols-2">
    <div>
      <label>AS-REP candidates (comma/space separated, blank = discovered)</label>
      <input type="text" bind:value={asrepUsers} placeholder="svc_sql, alice" />
      <button
        disabled={running !== null}
        on:click={runASREP}
        style="margin-top:0.5rem;"
      >
        {running === "asrep" ? "Running…" : "AS-REP roast"}
      </button>
    </div>
    <div>
      <label>Kerberoast (needs creds)</label>
      <button
        disabled={running !== null || !canAuthed}
        on:click={() => run("kerberoast", () => api.runKerberoast(""))}
      >
        {running === "kerberoast" ? "Running…" : "Kerberoast"}
      </button>
    </div>
  </div>
</div>

<div class="card">
  <h2>Password spray</h2>
  <div class="grid cols-2">
    <div>
      <label>Users (blank → user_file or discovered list)</label>
      <textarea rows="3" bind:value={sprayUsers}></textarea>
      <label style="margin-top:0.5rem;">Passwords</label>
      <textarea rows="3" bind:value={sprayPasswords}></textarea>
    </div>
    <div>
      <label>User file</label>
      <input type="text" bind:value={sprayUserFile} />
      <label style="margin-top:0.5rem;">Password file</label>
      <input type="text" bind:value={sprayPasswordFile} />
      <div class="row" style="margin-top:0.5rem;">
        <div>
          <label>Delay between rounds (s)</label>
          <input type="number" bind:value={sprayDelay} />
        </div>
        <label style="display:flex; gap:0.5rem; align-items:center; flex:0 0 auto; align-self:flex-end;">
          <input type="checkbox" bind:checked={sprayStopOnSuccess} />
          <span class="kbd">stop on success</span>
        </label>
      </div>
    </div>
  </div>
  <div style="margin-top:0.75rem;">
    <button disabled={running !== null} on:click={runSpray}>
      {running === "spray" ? "Running…" : "Spray"}
    </button>
  </div>
</div>

<div class="card">
  <h2>AD CS / trusts / vulns</h2>
  <div class="row">
    <button
      disabled={running !== null || !canAuthed}
      on:click={() => run("adcs", () => api.runADCS(""))}
    >
      {running === "adcs" ? "Running…" : "ADCS enum"}
    </button>
    <button
      disabled={running !== null || !results?.dcs?.length}
      on:click={() => run("trusts", () => api.runTrusts(""))}
    >
      {running === "trusts" ? "Running…" : "Trusts"}
    </button>
    <button
      disabled={running !== null || !results?.dcs?.length}
      on:click={() => run("vulns", () => api.runVulns(""))}
    >
      {running === "vulns" ? "Running…" : "Vuln sweep"}
    </button>
    <button
      disabled={running !== null || !cfg?.bhCeEnabled}
      on:click={() => run("ingest", api.ingestBloodHound)}
    >
      {running === "ingest" ? "Running…" : "Ingest to BloodHound"}
    </button>
  </div>
</div>

{#if lastError}
  <div class="card">
    <h2>Last error</h2>
    <pre class="error-text" style="white-space:pre-wrap;">{lastError}</pre>
  </div>
{/if}

{#if lastOutput}
  <div class="card">
    <h2>Last output — {lastOutput.id}</h2>
    <pre
      style="max-height:320px; overflow:auto; font-family:var(--mono); font-size:12px; background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:0.75rem;">
{JSON.stringify(lastOutput.data, null, 2)}</pre>
  </div>
{/if}
