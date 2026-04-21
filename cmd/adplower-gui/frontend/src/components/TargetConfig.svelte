<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import { api, type ConfigSnapshot, type TargetInput } from "../lib/api";

  export let cfg: ConfigSnapshot | null;

  const dispatch = createEventDispatcher<{ updated: void }>();

  let domain = cfg?.domain ?? "";
  let target = cfg?.target ?? "";
  let dc = cfg?.dc ?? "";
  let username = cfg?.username ?? "";
  let password = "";
  let ntHash = "";
  let dnsServer = cfg?.dnsServer ?? "";
  let bhNeo4jUri = cfg?.bhNeo4jUri ?? "bolt://localhost:7687";
  let bhNeo4jUser = cfg?.bhNeo4jUser ?? "neo4j";
  let bhNeo4jPass = "";
  let bhCeEnabled = cfg?.bhCeEnabled ?? false;
  let threads = cfg?.threads ?? 10;
  let status: string = "";

  // When the parent receives a fresh snapshot, sync the bindable fields so
  // edits aren't blown away on every refresh — only the secret fields, which
  // we never read back anyway.
  $: if (cfg) {
    if (domain === "") domain = cfg.domain;
    if (target === "") target = cfg.target;
    if (dc === "") dc = cfg.dc;
    if (username === "") username = cfg.username;
    if (dnsServer === "") dnsServer = cfg.dnsServer;
    threads = threads || cfg.threads;
  }

  async function save() {
    const payload: TargetInput = {
      domain,
      target,
      dc,
      username,
      dnsServer,
      bhNeo4jUri,
      bhNeo4jUser,
      bhCeEnabled,
      threads,
    };
    if (password) payload.password = password;
    if (ntHash) payload.ntHash = ntHash;
    if (bhNeo4jPass) payload.bhNeo4jPass = bhNeo4jPass;
    try {
      await api.setTarget(payload);
      status = "saved";
      password = "";
      ntHash = "";
      bhNeo4jPass = "";
      dispatch("updated");
      setTimeout(() => (status = ""), 2000);
    } catch (e) {
      status = "error: " + String(e);
    }
  }
</script>

<div class="card">
  <h2>Target</h2>
  <div class="grid cols-2">
    <div>
      <label>Domain</label>
      <input type="text" bind:value={domain} placeholder="lab.local" />
    </div>
    <div>
      <label>Target</label>
      <input
        type="text"
        bind:value={target}
        placeholder="10.0.0.10 or 10.0.0.0/24"
      />
    </div>
    <div>
      <label>Explicit DC</label>
      <input type="text" bind:value={dc} placeholder="dc01.lab.local" />
    </div>
    <div>
      <label>DNS server</label>
      <input type="text" bind:value={dnsServer} placeholder="10.0.0.1" />
    </div>
  </div>
</div>

<div class="card">
  <h2>Credentials</h2>
  <div class="grid cols-2">
    <div>
      <label>Username</label>
      <input type="text" bind:value={username} placeholder="svc_sql" />
    </div>
    <div>
      <label>Password</label>
      <input
        type="password"
        bind:value={password}
        placeholder="leave empty to keep existing"
      />
    </div>
    <div>
      <label>NT hash (hex)</label>
      <input type="password" bind:value={ntHash} placeholder="32-hex NT hash" />
    </div>
    <div>
      <label>Threads</label>
      <input type="number" bind:value={threads} min="1" max="128" />
    </div>
  </div>
</div>

<div class="card">
  <h2>BloodHound CE</h2>
  <div class="grid cols-3">
    <div>
      <label>Neo4j URI</label>
      <input type="text" bind:value={bhNeo4jUri} />
    </div>
    <div>
      <label>User</label>
      <input type="text" bind:value={bhNeo4jUser} />
    </div>
    <div>
      <label>Password</label>
      <input type="password" bind:value={bhNeo4jPass} />
    </div>
  </div>
  <div style="margin-top:0.5rem;">
    <label style="display:inline-flex; gap:0.5rem; align-items:center;">
      <input type="checkbox" bind:checked={bhCeEnabled} />
      <span>Enable BloodHound ingest</span>
    </label>
  </div>
</div>

<div class="row">
  <button on:click={save}>Save configuration</button>
  <span class="kbd">{status}</span>
</div>
