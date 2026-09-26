export const meta = {
  name: 'audit-egress',
  description: 'Give the audit log a way out: OTLP tracing, SIEM export, and signed offline-verifiable batches',
  whenToUse:
    'Finding F-05. Verification is cpctl audit verify and the records live in Postgres. No SIEM export, no webhook, no OpenTelemetry. Compliance teams work in the SIEM; a log readable only by its own CLI will not be watched.',
  phases: [
    { title: 'Design', detail: 'one design per egress target, in parallel' },
    { title: 'Integrate', detail: 'one agent builds the exporter interface and all targets' },
    { title: 'Verify', detail: 'end-to-end delivery, offline verification, and leak checking' },
  ],
}

const REPO = (args && args.repo) || '/home/iconbaypark2900/secure_ai_data_governance_control_plane'

const HOUSE = [
  'You are working in ' + REPO + ' -- a policy decision point for AI systems.',
  '',
  'House rules:',
  '- "make check" is the gate: ruff, mypy on control_plane/, pytest. 682 tests pass in ~14s.',
  '- ruff line-length 100, py312. mypy disallow_untyped_defs on control_plane/.',
  '- Fail closed. An export failure must never turn a deny into an allow, and must never block',
  '  the decision path. Egress is asynchronous and best-effort; the chain in Postgres is the',
  '  system of record.',
  '- ADR 0006 is absolute here: sensitive values never leave the process. The audit log is',
  '  deliberately thin -- it records that something was decided, by whom, about what, with payload',
  '  content present only as a keyed digest. An exporter that widens that is the worst possible',
  '  bug in this component, because it ships the data to a third system.',
  '- Metrics deliberately carry no policy key, principal or resource label, because cardinality',
  '  controlled by policy authors is a way to run a monitoring system out of memory. Respect that',
  '  reasoning when deciding what goes on a span.',
  '- Load-bearing decisions get an ADR in docs/adr/, numbered from 0017, in the existing voice.',
  '- Commits carry NO Co-Authored-By, Claude-Session, or any AI/assistant trailer.',
].join('\n')

const CONTEXT = [
  'What already exists:',
  '- control_plane/audit/chain.py -- HMAC-SHA256 over a canonical encoding, chained to the',
  '  predecessor. Many streams, each with its own chain and lock, plus checkpoint records in a',
  '  chain of their own. See ADR 0003 and ADR 0014.',
  '- control_plane/audit/service.py -- append and verify.',
  '- DecisionRecord carries correlation_id, so the plumbing for trace correlation is half built.',
  '- Prometheus metrics at /metrics, unauthenticated by scraper convention.',
  '- control_plane/cli.py -- cpctl audit verify.',
].join('\n')

const DESIGN_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['target', 'summary', 'schemaMapping', 'failureMode', 'configSurface', 'leakRisks'],
  properties: {
    target: { type: 'string' },
    summary: { type: 'string' },
    schemaMapping: { type: 'string', description: 'how a decision or audit record maps to this format' },
    failureMode: { type: 'string', description: 'what happens when the destination is unreachable' },
    configSurface: { type: 'array', items: { type: 'string' }, description: 'CP_ env vars added' },
    leakRisks: {
      type: 'array',
      items: { type: 'string' },
      description: 'every field that could carry sensitive content into the destination',
    },
  },
}

const VERIFY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['pass', 'detail', 'evidence'],
  properties: {
    pass: { type: 'boolean' },
    detail: { type: 'string' },
    evidence: { type: 'string' },
  },
}

phase('Design')
const TARGETS = [
  {
    key: 'otlp-traces',
    brief:
      'OpenTelemetry tracing across the decision path. A decision spanning enforcement point -> ' +
      'control plane -> model is exactly a span tree, and correlation_id already exists on the ' +
      'record. Design the span structure, what belongs on a span versus what must never (apply the ' +
      'same cardinality and sensitivity reasoning the metrics use), and how a PEP propagates ' +
      'context into the control plane. Cover both SDKs and both PEPs.',
  },
  {
    key: 'siem-stream',
    brief:
      'Streaming export of audit records to a SIEM. Design one exporter interface with concrete ' +
      'implementations for Splunk HEC and a generic HTTP/webhook sink, plus an OCSF-shaped mapping ' +
      'so Sentinel and Chronicle can ingest without bespoke work. Handle batching, retry with ' +
      'backpressure, at-least-once delivery, and a durable cursor so a restart does not silently ' +
      'skip records. Note explicitly what happens when the destination is down for a day.',
  },
  {
    key: 'signed-batches',
    brief:
      'THIS IS THE DIFFERENTIATED ONE -- design it most carefully. Periodic export of sealed audit ' +
      'batches to object storage, verifiable OFFLINE by a third party who does not have database ' +
      'access. The chain is keyed HMAC, so a verifier needs the key -- which is exactly what you ' +
      'must not hand an external auditor. Solve that: consider a detached signature over batch ' +
      'digests using an asymmetric key, publishing checkpoint digests, or a verification key ' +
      'distinct from the sealing key. State plainly what an external verifier can and cannot prove ' +
      'under your design. Commercial products in this space do not offer this, so getting the ' +
      'security argument right matters more than shipping quickly.',
  },
  {
    key: 'cli-and-ops',
    brief:
      'The operator surface. Extend cpctl with export, replay-from-cursor, and an offline verify ' +
      'that takes exported batches rather than a database. Design the health and metrics story: ' +
      'how does an operator learn that egress has been silently failing for six hours? The project ' +
      'already treats silence as a state rather than a default -- unreported decisions are ' +
      'surfaced, not assumed fine -- so apply that same principle here.',
  },
]

const designs = (
  await parallel(
    TARGETS.map((t) => () =>
      agent(
        [
          HOUSE,
          '',
          CONTEXT,
          '',
          'Design one egress target. Read the audit package before proposing anything.',
          '',
          'Your target: ' + t.key,
          t.brief,
          '',
          'Enumerate leakRisks exhaustively -- every field you propose to emit that could carry',
          'content rather than metadata. Do not edit anything.',
        ].join('\n'),
        { label: 'design:' + t.key, phase: 'Design', schema: DESIGN_SCHEMA }
      )
    )
  )
).filter(Boolean)

log(designs.length + ' egress designs; ' + designs.reduce((n, d) => n + d.leakRisks.length, 0) + ' leak risks flagged')

phase('Integrate')
const applied = await agent(
  [
    HOUSE,
    '',
    CONTEXT,
    '',
    'Four egress designs follow. They were produced independently -- reconcile them into one',
    'coherent exporter abstraction rather than four bolt-ons.',
    '',
    JSON.stringify(designs, null, 2),
    '',
    'Requirements:',
    '- Every exporter is off by default. A deployment configuring none must behave exactly as today',
    '  and the existing 682 tests must pass unchanged.',
    '- Export is asynchronous and never on the decision path. Prove the decision latency is',
    '  unchanged with an exporter enabled -- measure it, do not assert it.',
    '- Address every leak risk the designs flagged. Add a test that fails if a payload value, a',
    '  detokenised value, or a finding value can reach an exporter.',
    '- Failure is visible. A silently failing exporter must show up in metrics and in a cpctl',
    '  command.',
    '- Write the ADR for the signed-batch design specifically -- the asymmetric verification',
    '  argument is load-bearing and needs to be written down.',
    '- Run "make check" and leave it green.',
    '',
    'Do not commit. Leave the working tree dirty for review.',
  ].join('\n'),
  { label: 'integrate:exporters', phase: 'Integrate', effort: 'high' }
)

phase('Verify')
const CHECKS = [
  {
    key: 'no-leak',
    probe:
      'You are trying to get sensitive content out through an exporter. Drive decisions carrying ' +
      'SSNs, credentials and card numbers, with redaction, tokenisation and detokenisation in play, ' +
      'and inspect every byte each exporter emits. Check error paths and exception messages too -- ' +
      'a stack trace carrying a payload is the classic version of this bug. Report pass=false if ' +
      'you find any content value anywhere in the emitted data.',
  },
  {
    key: 'offline-verify',
    probe:
      'You are an external auditor with exported batches and NO database access and NO sealing key. ' +
      'Can you verify the records are authentic and unaltered? Can you detect a batch removed ' +
      'entirely -- the gap the checkpoint design exists to close? Actually perform the verification ' +
      'against real exported data and report what you could and could not prove.',
  },
  {
    key: 'failure-and-load',
    probe:
      'You are breaking the egress path. Kill the destination mid-batch, make it return 500s, make ' +
      'it hang, restart the service with a partial cursor, and fill the queue. The decision path ' +
      'must keep working and must never turn a deny into an allow. Records must not be silently ' +
      'lost, and the operator must be able to find out. Measure decision latency with exporters ' +
      'enabled and under backpressure.',
  },
]

const verdicts = (
  await parallel(
    CHECKS.map((c) => () =>
      agent(
        [
          HOUSE,
          '',
          CONTEXT,
          '',
          'Egress has been implemented. Summary:',
          applied || '(unavailable -- inspect with git diff)',
          '',
          'You are an adversary, not a reviewer. Default to pass=false unless you demonstrated',
          'the property holds.',
          '',
          'Your lens: ' + c.key,
          c.probe,
        ].join('\n'),
        { label: 'verify:' + c.key, phase: 'Verify', schema: VERIFY_SCHEMA, effort: 'high' }
      )
    )
  )
).filter(Boolean)

const failed = verdicts.filter((v) => !v.pass)
log(failed.length ? failed.length + ' verification(s) failed' : 'all verifications passed')

return { designs, applied, verdicts, failures: failed, clean: failed.length === 0 }
