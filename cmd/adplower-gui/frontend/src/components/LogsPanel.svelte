<script lang="ts">
  import { onMount } from "svelte";
  import { api, type LogEvent } from "../lib/api";

  const MAX = 500;
  let entries: LogEvent[] = [];
  let container: HTMLDivElement | undefined;

  function pushLog(ev: LogEvent) {
    entries = [...entries.slice(-MAX + 1), ev];
    queueMicrotask(() => {
      if (container) container.scrollTop = container.scrollHeight;
    });
  }

  onMount(() => api.onEvent<LogEvent>("log", pushLog));

  function clear() {
    entries = [];
  }

  function color(scope: string) {
    switch (scope) {
      case "asrep":
      case "kerberoast":
        return "var(--warn)";
      case "spray":
        return "var(--accent)";
      case "vulns":
        return "var(--error)";
      case "bloodhound":
        return "var(--success)";
      case "ldap":
      case "smb":
      case "dns":
        return "var(--accent-2)";
      default:
        return "var(--fg-muted)";
    }
  }
</script>

<div style="display:flex; flex-direction:column; height:100%;">
  <div
    style="display:flex; align-items:center; justify-content:space-between; padding:0.35rem 0.75rem; border-bottom:1px solid var(--border);"
  >
    <span class="kbd">LOGS · {entries.length}</span>
    <button on:click={clear} style="padding:0.2rem 0.55rem; font-size:11px;">clear</button>
  </div>
  <div
    bind:this={container}
    style="flex:1; overflow:auto; font-family:var(--mono); font-size:12px; padding:0.5rem 0.75rem;"
  >
    {#each entries as e}
      <div>
        <span class="kbd" style="margin-right:0.5rem;">{e.time.slice(11, 19)}</span>
        <span style="color:{color(e.scope)}; margin-right:0.5rem;">{e.scope}</span>
        <span>{e.msg}</span>
      </div>
    {/each}
    {#if entries.length === 0}
      <div class="kbd">No output yet. Run a module from the Modules tab.</div>
    {/if}
  </div>
</div>
