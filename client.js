window.__ModuleLoader__.load({
  id: 'dsh-source-recovery',
  factory: (require) => {
    const module = { exports: {} };
    const exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
    const React = require('react');
    const { useEffect, useState } = React;
    const h = React.createElement;

    const PANEL_ID = 'source-recovery';
    const API_BASE = '/plugins/dsh-source-recovery/api';
    const COLORS = {
      text: 'var(--dsw-alias-label-primary, #e8e8ea)',
      secondary: 'var(--dsw-alias-label-secondary, #a9adb6)',
      tertiary: 'var(--dsw-alias-label-tertiary, #7d818a)',
      border: 'var(--dsw-alias-border-secondary, rgba(255,255,255,.12))',
      bg: 'var(--dsw-alias-bg-elevated, rgba(255,255,255,.04))',
      ok: 'var(--dsw-alias-state-success, #63d19b)',
      warn: 'var(--dsw-alias-state-warning, #e2b45c)',
      bad: 'var(--dsw-alias-state-error, #ef7a7a)',
      accent: 'var(--dsw-alias-brand-primary, #7aa2ff)',
    };
    const mono = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

    const styles = {
      root: { height: '100%', overflow: 'auto', padding: '24px 28px 40px', color: COLORS.text, display: 'flex', flexDirection: 'column', gap: 18, boxSizing: 'border-box' },
      header: { display: 'flex', alignItems: 'flex-start', gap: 14, flexWrap: 'wrap' },
      icon: { width: 38, height: 38, borderRadius: 10, background: 'linear-gradient(135deg, rgba(122,162,255,.35), rgba(122,162,255,.08))', border: `1px solid ${COLORS.border}`, display: 'grid', placeItems: 'center', flex: 'none' },
      title: { margin: 0, fontSize: 20, fontWeight: 650, letterSpacing: '.2px' },
      subtitle: { margin: '2px 0 0', color: COLORS.secondary, fontSize: 12.5, lineHeight: 1.5, maxWidth: 760 },
      notice: { border: `1px solid ${COLORS.border}`, background: COLORS.bg, borderRadius: 10, padding: '10px 14px', fontSize: 12.5, color: COLORS.secondary, lineHeight: 1.55 },
      toolbar: { display: 'flex', gap: 8, flexWrap: 'wrap' },
      button: { border: `1px solid ${COLORS.border}`, background: COLORS.bg, color: COLORS.text, borderRadius: 8, padding: '6px 12px', fontSize: 12.5, cursor: 'pointer' },
      card: { border: `1px solid ${COLORS.border}`, background: COLORS.bg, borderRadius: 12, padding: '14px 16px' },
      cardTitle: { margin: '0 0 10px', fontSize: 13, fontWeight: 600, letterSpacing: '.2px' },
      table: { width: '100%', borderCollapse: 'collapse', fontSize: 12.5 },
      th: { textAlign: 'left', color: COLORS.tertiary, fontWeight: 500, padding: '4px 8px', borderBottom: `1px solid ${COLORS.border}` },
      td: { padding: '6px 8px', borderBottom: `1px solid ${COLORS.border}`, color: COLORS.text, verticalAlign: 'top' },
      mono: { fontFamily: mono, fontSize: 11.5, color: COLORS.secondary },
      pill: { display: 'inline-block', padding: '1px 8px', borderRadius: 999, fontSize: 11, fontFamily: mono, border: `1px solid ${COLORS.border}`, color: COLORS.secondary },
      grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(190px, 1fr))', gap: 8 },
      cell: { border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: '8px 10px', display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 12.5 },
      error: { color: COLORS.bad, fontSize: 12.5 },
      muted: { color: COLORS.tertiary, fontSize: 12 },
    };

    function statusColor(ok) { return ok ? COLORS.ok : COLORS.tertiary; }

    function LevelPill({ level }) {
      return h('span', { style: styles.pill }, level);
    }

    function Header() {
      return h('div', { style: styles.header },
        h('div', { style: styles.icon },
          h('svg', { width: 22, height: 22, viewBox: '0 0 24 24', fill: 'none', stroke: COLORS.accent, strokeWidth: 1.8, strokeLinecap: 'round', strokeLinejoin: 'round' },
            h('path', { d: 'M4 6h8M4 12h5M4 18h7' }),
            h('path', { d: 'M14 8l6 4-6 4V8z' }),
          )),
        h('div', {},
          h('h1', { style: styles.title }, 'Source Recovery'),
          h('p', { style: styles.subtitle },
            'Reverse everything toward source — with honest levels. S0 exact source, S1 near-source, S2 pseudo-source, S3 assembly/metadata, S4 behavior only. Authorized targets only; nothing is executed and nothing leaves the machine.'),
        ),
      );
    }

    function Workbench() {
      const [capabilities, setCapabilities] = useState(null);
      const [doctor, setDoctor] = useState(null);
      const [selftest, setSelftest] = useState(null);
      const [error, setError] = useState('');
      const [busy, setBusy] = useState('');
      const [tick, setTick] = useState(0);

      useEffect(() => {
        let cancelled = false;
        async function load() {
          try {
            const [capResponse, docResponse] = await Promise.all([
              fetch(`${API_BASE}/capabilities`, { headers: { accept: 'application/json' } }),
              fetch(`${API_BASE}/doctor`, { headers: { accept: 'application/json' } }),
            ]);
            const cap = await capResponse.json();
            const doc = await docResponse.json();
            if (cancelled) return;
            setCapabilities(cap);
            setDoctor(doc);
            setError(cap.ok === false ? `${cap.code}: ${cap.message}` : '');
          } catch (cause) {
            if (!cancelled) setError(cause instanceof Error ? cause.message : 'failed to load diagnostics');
          }
        }
        load();
        return () => { cancelled = true; };
      }, [tick]);

      async function runSelftest() {
        setBusy('selftest');
        setError('');
        try {
          const response = await fetch(`${API_BASE}/selftest`, { headers: { accept: 'application/json' } });
          setSelftest(await response.json());
        } catch (cause) {
          setError(cause instanceof Error ? cause.message : 'self-test failed');
        } finally {
          setBusy('');
        }
      }

      const families = capabilities?.families ?? [];
      const backends = doctor?.backends ?? capabilities?.backends ?? {};
      const levels = capabilities?.levels ?? {};
      const health = doctor?.temporaryDirectory;

      return h('div', { style: styles.root },
        h(Header),
        h('div', { style: styles.notice },
          h('strong', { style: { color: COLORS.text } }, 'Authorization and evidence policy. '),
          'All recovery tools require an explicit authorized=true flag. The plugin never executes a target, never contacts the network, and never presents a lower recovery level as recovered source. Same-process DSH plugins are not isolated by tool approvals. Use reverse_bundle to produce a hash-verified handoff ZIP and reverse_verify to check it independently.'),
        h('div', { style: styles.toolbar },
          h('button', { style: styles.button, onClick: () => setTick((value) => value + 1), type: 'button' }, 'Refresh diagnostics'),
          h('button', { style: styles.button, onClick: runSelftest, disabled: busy === 'selftest', type: 'button' }, busy === 'selftest' ? 'Running self-test…' : 'Run core self-test'),
          error ? h('span', { style: styles.error }, error) : null,
        ),
        h('div', { style: styles.grid },
          h('div', { style: styles.cell }, h('span', null, 'Plugin'), h('span', { style: styles.mono }, capabilities?.generatedAt ? `v0.2.0 · ${capabilities.generatedAt.slice(11, 19)}Z` : 'v0.2.0')),
          h('div', { style: styles.cell }, h('span', null, 'Temp workspace'), h('span', { style: { color: statusColor(health?.writable) } }, health ? (health.writable ? 'writable' : 'blocked') : '—')),
          h('div', { style: styles.cell }, h('span', null, 'REA MCP'), h('span', { style: { color: statusColor(doctor?.backends?.rea?.available) } }, doctor?.backends?.rea?.available ? 'detected' : 'not detected')),
          h('div', { style: styles.cell }, h('span', null, 'Backends'), h('span', { style: styles.mono }, `${Object.values(backends).filter((entry) => entry.available).length} available`)),
          h('div', { style: styles.cell }, h('span', null, 'Evidence bundle'), h('span', { style: styles.mono }, 'hash-verified ZIP')),
        ),
        h('section', { style: styles.card },
          h('h2', { style: styles.cardTitle }, 'Recovery levels'),
          h('div', { style: styles.grid },
            Object.values(levels).map((level) => h('div', { key: level.id, style: styles.cell },
              h('span', { style: styles.pill }, level.id),
              h('span', { style: styles.muted }, level.name),
            )),
          ),
        ),
        h('section', { style: styles.card },
          h('h2', { style: styles.cardTitle }, 'Target families and local ceiling'),
          families.length === 0 && !error ? h('div', { style: styles.muted }, 'Loading capability matrix…')
            : h('table', { style: styles.table },
              h('thead', null, h('tr', null,
                h('th', { style: styles.th }, 'Family'), h('th', { style: styles.th }, 'Local ceiling'),
                h('th', { style: styles.th }, 'With REA'), h('th', { style: styles.th }, 'Backends'),
              )),
              h('tbody', null, families.map((family) => h('tr', { key: family.id },
                h('td', { style: styles.td }, h('div', null, family.title), h('div', { style: styles.mono }, family.note)),
                h('td', { style: styles.td }, h(LevelPill, { level: family.bestLocal })),
                h('td', { style: styles.td }, h(LevelPill, { level: family.bestWithRea })),
                h('td', { style: styles.td }, family.backendState.map((backend) => h('span', {
                  key: backend.id,
                  style: { ...styles.pill, marginRight: 4, color: statusColor(backend.available), borderColor: backend.available ? COLORS.ok : COLORS.border },
                }, backend.id))),
              ))),
            ),
        ),
        h('section', { style: styles.card },
          h('h2', { style: styles.cardTitle }, 'Toolchains'),
          h('div', { style: styles.grid },
            Object.entries(backends).filter(([id]) => id !== 'rea').map(([id, backend]) => h('div', { key: id, style: styles.cell },
              h('div', null,
                h('div', { style: styles.mono }, id),
                h('div', { style: styles.muted }, backend.available ? (backend.version ?? 'available') : 'not installed'),
              ),
              h('span', { style: { color: statusColor(backend.available), fontSize: 16 } }, backend.available ? '●' : '○'),
            )),
          ),
        ),
        selftest ? h('section', { style: styles.card },
          h('h2', { style: styles.cardTitle }, `Self-test · ${selftest.ok ? 'passed' : 'failed'}`),
          selftest.counts ? h('div', { style: styles.mono }, `${selftest.counts.passed} passed · ${selftest.counts.failed} failed · ${selftest.counts.unavailable} unavailable`) : null,
          h('ul', { style: { margin: '8px 0 0', paddingLeft: 18, fontSize: 12.5, lineHeight: 1.6 } },
            (selftest.checks ?? []).map((check) => h('li', { key: check.id, style: { color: check.status === 'passed' ? COLORS.text : COLORS.bad } },
              `${check.id}: ${check.status} — ${check.detail}`,
            )),
          ),
        ) : null,
        h('div', { style: styles.muted },
          'Workbench is read-only: it exposes no target paths, no file contents and no write operations. Run recovery through the reverse_* tools or the CLI.'),
      );
    }

    function apply(ctx) {
      ctx.slots.inject('main', () => ctx.slots.register({ name: 'main', key: PANEL_ID }, Workbench));
      ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({
        name: 'sidebar.panellist', id: PANEL_ID, order: 42, label: 'Reverse',
      }, function ReverseIcon() {
        return h('svg', { width: 18, height: 18, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round', strokeLinejoin: 'round' },
          h('path', { d: 'M4 6h8M4 12h5M4 18h7' }),
          h('path', { d: 'M14 8l6 4-6 4V8z' }),
        );
      }));
    }

    exports.name = 'dsh-source-recovery-client';
    exports.apply = apply;
    exports.inject = ['slots', 'layout'];
    return module.exports;
  },
});
