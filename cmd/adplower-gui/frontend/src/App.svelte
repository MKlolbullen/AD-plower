<script lang="ts">
  import { onMount } from "svelte";
  import TargetConfig from "./components/TargetConfig.svelte";
  import ModuleRunner from "./components/ModuleRunner.svelte";
  import Dashboard from "./components/Dashboard.svelte";
  import LogsPanel from "./components/LogsPanel.svelte";
  import { api, type ConfigSnapshot, type ReconResults } from "./lib/api";

  type View = "target" | "modules" | "dashboard";

  let view: View = "target";
  let cfg: ConfigSnapshot | null = null;
  let results: ReconResults | null = null;

  const views: { id: View; label: string; desc: string }[] = [
    { id: "target", label: "Target", desc: "Domain, DC, credentials" },
    { id: "modules", label: "Modules", desc: "Run recon / attacks" },
    { id: "dashboard", label: "Dashboard", desc: "Live evidence" },
  ];

  async function refresh() {
    try {
      cfg = await api.getConfig();
      results = await api.getResults();
    } catch (e) {
      // Wails bridge may not be ready yet; swallow and retry on next tick.
    }
  }

  onMount(() => {
    refresh();
    const unsub = api.onEvent<ReconResults>("results:updated", (r) => {
      results = r;
    });
    return () => unsub();
  });
</script>

<div class="app">
  <aside class="sidebar">
    <h1>AD-PLOWER</h1>
    {#each views as v}
      <button
        class="nav-item"
        class:active={view === v.id}
        on:click={() => (view = v.id)}
      >
        <div><strong>{v.label}</strong></div>
        <div class="kbd">{v.desc}</div>
      </button>
    {/each}

    <div style="margin-top:auto;">
      <div class="kbd">workspace</div>
      <div style="font-family:var(--mono); font-size:11px; word-break:break-all;">
        {cfg?.workspace ?? ""}
      </div>
    </div>
  </aside>

  <header class="topbar">
    <span class="badge">
      <strong>Domain</strong>{cfg?.domain || "—"}
    </span>
    <span class="badge">
      <strong>DC</strong>{cfg?.dc || results?.dcs?.[0] || "—"}
    </span>
    <span class="badge">
      <strong>User</strong>{cfg?.username || "—"}
    </span>
    <span class="badge">
      <strong>BH CE</strong>{cfg?.bhCeEnabled ? "on" : "off"}
    </span>
    <span style="flex:1"></span>
    <span class="kbd">updated {results?.updated_at ?? ""}</span>
  </header>

  <main class="main">
    {#if view === "target"}
      <TargetConfig {cfg} on:updated={() => refresh()} />
    {:else if view === "modules"}
      <ModuleRunner {cfg} {results} on:updated={() => refresh()} />
    {:else if view === "dashboard"}
      <Dashboard {results} />
    {/if}
  </main>

  <section class="logs">
    <LogsPanel />
  </section>
</div>
