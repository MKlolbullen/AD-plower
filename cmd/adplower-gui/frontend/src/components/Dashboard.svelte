<script lang="ts">
  import type { ReconResults } from "../lib/api";

  export let results: ReconResults | null;

  $: asrepCount = results ? Object.keys(results.asrep_hashes || {}).length : 0;
  $: tgsCount = results ? Object.keys(results.tgs_hashes || {}).length : 0;
  $: credCount = results?.valid_creds?.length ?? 0;
  $: vulnCount = results?.vulns?.length ?? 0;
</script>

<div class="grid cols-4">
  <div class="stat">
    <div class="label">DCs</div>
    <div class="value">{results?.dcs?.length ?? 0}</div>
  </div>
  <div class="stat">
    <div class="label">Users</div>
    <div class="value">{results?.users?.length ?? 0}</div>
  </div>
  <div class="stat">
    <div class="label">Computers</div>
    <div class="value">{results?.computers?.length ?? 0}</div>
  </div>
  <div class="stat">
    <div class="label">Groups</div>
    <div class="value">{results?.groups?.length ?? 0}</div>
  </div>
  <div class="stat">
    <div class="label">Trusts</div>
    <div class="value">{results?.trusts?.length ?? 0}</div>
  </div>
  <div class="stat">
    <div class="label">AS-REP hashes</div>
    <div class="value">{asrepCount}</div>
  </div>
  <div class="stat">
    <div class="label">TGS hashes</div>
    <div class="value">{tgsCount}</div>
  </div>
  <div class="stat">
    <div class="label">Valid creds</div>
    <div class="value">{credCount}</div>
  </div>
</div>

{#if vulnCount > 0}
  <div class="card">
    <h2>Vulnerability findings</h2>
    <div class="list">
      {#each results?.vulns ?? [] as v}
        <div>
          <span class="pill {v.severity}">{v.severity}</span>
          <strong>{v.name}</strong>
          <span class="kbd">@ {v.target}</span>
          — {v.notes}
        </div>
      {/each}
    </div>
  </div>
{/if}

{#if results?.dcs?.length}
  <div class="card">
    <h2>Domain controllers</h2>
    <div class="list">
      {#each results.dcs as dc}
        <div>{dc}</div>
      {/each}
    </div>
  </div>
{/if}

{#if results?.trusts?.length}
  <div class="card">
    <h2>Trusts</h2>
    <div class="list">
      {#each results.trusts as t}
        <div>
          <strong>{t.name}</strong>
          <span class="kbd">dir={t.direction} type={t.type} attrs=0x{t.attrs.toString(16)}</span>
        </div>
      {/each}
    </div>
  </div>
{/if}

{#if results?.adcs_cas?.length}
  <div class="card">
    <h2>AD CS CAs</h2>
    <div class="list">
      {#each results.adcs_cas as ca}
        <div>
          <strong>{ca.ca_name}</strong>
          <span class="kbd">@ {ca.dns_name} — {ca.templates.length} templates</span>
        </div>
      {/each}
    </div>
  </div>
{/if}

{#if results?.valid_creds?.length}
  <div class="card">
    <h2>Captured credentials</h2>
    <div class="list">
      {#each results.valid_creds as c}
        <div class="success-text">
          <strong>{c.user}</strong>
          <span class="kbd">:{c.password}</span>
          <span class="kbd">({c.source})</span>
        </div>
      {/each}
    </div>
  </div>
{/if}

{#if asrepCount > 0}
  <div class="card">
    <h2>AS-REP hashes</h2>
    <div class="list">
      {#each Object.entries(results?.asrep_hashes ?? {}) as [user, hash]}
        <div>
          <strong>{user}</strong>
          <span class="kbd" style="word-break:break-all;">{hash}</span>
        </div>
      {/each}
    </div>
  </div>
{/if}

{#if tgsCount > 0}
  <div class="card">
    <h2>TGS hashes</h2>
    <div class="list">
      {#each Object.entries(results?.tgs_hashes ?? {}) as [user, hash]}
        <div>
          <strong>{user}</strong>
          <span class="kbd" style="word-break:break-all;">{hash}</span>
        </div>
      {/each}
    </div>
  </div>
{/if}
