export const meta = {
  name: 'verify-findings',
  description: 'Re-verify all ten assessment findings against current HEAD and report what is actually closed',
  whenToUse:
    'Run after any remediation workflow, or periodically, to close the loop on the August 2026 assessment. Claims of closure are adversarially re-checked: a finding counts as closed only when someone tried to prove it was still open and failed.',
  phases: [
    { title: 'Check', detail: 'one agent per finding, against current HEAD' },
    { title: 'Challenge', detail: 'adversary on every finding claimed closed' },
    { title: 'Critique', detail: 'what regressed, and what has no finding yet' },
  ],
}

const REPO = (args && args.repo) || '/home/iconbaypark2900/secure_ai_data_governance_control_plane'

const HOUSE = [
  'You are working in ' + REPO + ' -- a policy decision point for AI systems.',
  '',
  'IMPORTANT -- verify the WORKING TREE, not HEAD. HEAD is 700db9a and is the untouched baseline',
  'the original assessment was written against. All remediation so far is UNCOMMITTED: 29 modified',
  'files plus docs/adr/0017-*.md, docs/adr/0018-*.md,',
  'migrations/versions/0006_decision_unsupported_obligations.py and',
  'scripts/check_removed_obligations.py. Read files normally and run the suite normally -- that is',
  'the tree under test. Do NOT use "git show HEAD:<path>" to read code; that reads the pre-fix',
  'version and will tell you every finding is still open.',
  '',
  'Verify against the code as it is now. Do not trust the README, the ADRs, or this workflow own',
  'description -- the original assessment exists precisely because the README described behaviour',
  'the code did not have. Read the source and run things.',
  '',
  '"make check" runs ruff, mypy on control_plane/, and pytest. At assessment time the baseline was',
  '682 tests passing in about 14s on SQLite with 44 skipped and 79% coverage. On the current tree',
  'it should be 718 passing, 44 skipped, with ruff and mypy clean and 46 TypeScript tests passing.',
  'If those numbers do not reproduce, say so -- that is itself a finding.',
  '',
  'Two remediation passes have run against F-01 only. They closed it, and each introduced',
  'regressions by moving unimplemented claims OUT of the obligations block and INTO policy',
  'descriptions and prose, where no type check reaches them. Treat that pattern as a live hazard',
  'when you assess any finding, and report any instance you find under the critique phase.',
].join('\n')

const FINDINGS = [
  {
    id: 'F-01',
    severity: 'critical',
    title: 'annotate, log and ttl are declared control-plane-executed and do nothing',
    original:
      'model.py:110-122 declares them Executor.CONTROL_PLANE; model.py:156 derives ' +
      'CONTROL_PLANE_OBLIGATIONS from that; pdp.py:76 sets SELF_EXECUTABLE from it; pdp.py:264 ' +
      'excludes them from unsupported_obligations; sdk client.py:50 lists all three as satisfied; ' +
      'pdp.py:294-314 executes only redact; seed/policies.yaml:265 ships an annotate obligation.',
    closedWhen:
      'Either each type is executed by real code, or all three are Executor.ENFORCEMENT_POINT so ' +
      'enforce() raises. Prove it by driving a decision carrying each type and observing what happens.',
  },
  {
    id: 'F-02',
    severity: 'critical',
    title: 'the audit chain attributes actions to a key, not a person',
    original:
      'auth/service.py:40 -- identity returns record.name. About fourteen sites in api/v1/ seal ' +
      'with actor=caller.identity. ui/src/lib/api.ts:26 -- console auth is a raw API key in ' +
      'sessionStorage, with no OIDC and no per-user identity.',
    closedWhen:
      'A human-performed admin action seals with a human subject that is distinguishable from a ' +
      'machine key, and a caller cannot choose its own actor value. Prove both.',
  },
  {
    id: 'F-03',
    severity: 'high',
    title: 'detectors are US and English only while GDPR is claimed throughout',
    original:
      '28 detectors, of which IBAN is the only non-US identifier. No UK NINO or NHS number, no ' +
      'German Steuer-ID, no French INSEE, no Italian codice fiscale, no Spanish DNI, no Canadian ' +
      'SIN, no Aadhaar, no My Number. Context keywords are English only.',
    closedWhen:
      'The major EU jurisdictions have identifier detectors with real structural checks, and ' +
      'enabling them changes nothing for a deployment that has not opted in.',
  },
  {
    id: 'F-04',
    severity: 'high',
    title: 'throughput ceiling for an inline data-path component',
    original:
      '50 req/s on one worker, 107 on four, p95 368ms at 8KB payloads. About 0.6ms/KB CPU-bound, ' +
      'and Python re only partially releases the GIL, so one worker is one core.',
    closedWhen:
      'A reproducible benchmark exists AND measured per-KB scan cost has materially improved. Run ' +
      'the benchmark yourself; do not quote a number from a commit message or an ADR.',
  },
  {
    id: 'F-05',
    severity: 'medium',
    title: 'the audit log has no way out',
    original:
      'Verification is cpctl audit verify and records live in Postgres. No SIEM export, no webhook, ' +
      'no OpenTelemetry. correlation_id exists on the record but nothing traces.',
    closedWhen:
      'Audit records can reach an external system, and an external party can verify exported ' +
      'records without database access. Exercise both paths rather than reading the code.',
  },
  {
    id: 'F-06',
    severity: 'medium',
    title: 'nothing is published and deployment stops at Docker Compose',
    original:
      'Neither SDK is on PyPI or npm. No image on any registry. No Helm chart, no Kubernetes ' +
      'manifests, no Terraform. No documented key backup or DR procedure.',
    closedWhen:
      'A stranger can install the SDK from a package registry and run the service from a published ' +
      'image without cloning the repository. Check whether artifacts are actually published, not ' +
      'merely whether publish configuration exists.',
  },
  {
    id: 'F-07',
    severity: 'medium',
    title: 'the simulator cannot replay history',
    original:
      'api/v1/decisions.py:83 -- /v1/simulate evaluates one request. Nothing answers what a ' +
      'candidate policy set would have done to recorded traffic.',
    closedWhen:
      'A candidate policy set can be replayed against recorded decisions, and the output cannot be ' +
      'read as covering conditions it was unable to evaluate.',
  },
  {
    id: 'F-08',
    severity: 'medium',
    title: 'approvals have no notification path',
    original:
      'require_approval parks a decision until someone happens to look at the console. notify was ' +
      'removed as unimplemented under ADR 0010 and never returned.',
    closedWhen:
      'Approval creation reaches a human through some channel without anyone polling a UI.',
  },
  {
    id: 'F-09',
    severity: 'low',
    title: 'multi-tenancy is a day-one non-goal never revisited',
    original:
      'No tenant concept in the model. docs/LIAISON_PROJECT_BRIEF.md, dated 2026-05-30, lists it ' +
      'as a non-goal, points at a stale ~/dataScience/ path, and calls the project a prototype.',
    closedWhen:
      'The decision is recorded deliberately -- an ADR, plus the README stating it -- whichever way ' +
      'it went, and the stale brief is no longer the record of it.',
  },
  {
    id: 'F-10',
    severity: 'low',
    title: 'no detector for names or addresses',
    original:
      'pii.name and pii.address are labels with no detector. Documented honestly, but a name is ' +
      'the canonical personal datum under GDPR.',
    closedWhen:
      'An optional probabilistic detector exists and is clearly surfaced as probabilistic, or the ' +
      'project has recorded a deliberate decision not to add one.',
  },
]

const STATUS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['id', 'status', 'evidence', 'detail'],
  properties: {
    id: { type: 'string' },
    status: { type: 'string', enum: ['closed', 'partial', 'open', 'regressed'] },
    evidence: { type: 'string', description: 'file:line or command output you actually produced' },
    detail: { type: 'string' },
  },
}

const CHALLENGE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['id', 'stillOpen', 'attack', 'evidence'],
  properties: {
    id: { type: 'string' },
    stillOpen: { type: 'boolean' },
    attack: { type: 'string' },
    evidence: { type: 'string' },
  },
}

log('re-verifying ' + FINDINGS.length + ' findings against current HEAD')

const results = (
  await pipeline(
    FINDINGS,
    (f) =>
      agent(
        [
          HOUSE,
          '',
          'Finding ' + f.id + ' (' + f.severity + '): ' + f.title,
          '',
          'As originally found:',
          f.original,
          '',
          'Closed when:',
          f.closedWhen,
          '',
          'Determine the current status against HEAD. Read the code, run commands, produce evidence.',
          'Use "regressed" if it was addressed and has since broken again. Use "partial" honestly',
          'rather than rounding up to closed -- a finding half-fixed and reported closed is worse',
          'than one reported open, because nobody looks at it again.',
          '',
          'Do not edit anything.',
        ].join('\n'),
        { label: 'check:' + f.id, phase: 'Check', schema: STATUS_SCHEMA }
      ),
    (result, f) => {
      if (!result || result.status !== 'closed') return result
      return agent(
        [
          HOUSE,
          '',
          'Finding ' + f.id + ': ' + f.title,
          '',
          'A prior agent reports this CLOSED, on this evidence:',
          result.evidence,
          result.detail,
          '',
          'You are an adversary. Try to prove it is still open. Look specifically for: a fix applied',
          'on one path but not another (Python SDK but not TypeScript, control plane but not the',
          'PEPs); a test that passes because it was written to match the implementation rather than',
          'the requirement; documentation updated without the code; and a fix that holds on the',
          'happy path but not under error, concurrency, or an unusual configuration.',
          '',
          'Return stillOpen=true only for something you actually demonstrated. If you genuinely',
          'could not break it, say so -- a confirmed close is a real result.',
        ].join('\n'),
        { label: 'challenge:' + f.id, phase: 'Challenge', schema: CHALLENGE_SCHEMA, effort: 'high' }
      ).then(function (ch) {
        if (ch && ch.stillOpen) {
          return {
            id: result.id,
            status: 'partial',
            evidence: ch.evidence,
            detail: result.detail + ' | ADVERSARY: ' + ch.attack,
            challenge: ch,
          }
        }
        return {
          id: result.id,
          status: result.status,
          evidence: result.evidence,
          detail: result.detail,
          challenge: ch,
          confirmed: true,
        }
      })
    }
  )
).filter(Boolean)

const byStatus = { closed: [], partial: [], open: [], regressed: [] }
for (const r of results) {
  if (byStatus[r.status]) byStatus[r.status].push(r.id)
}
log(
  'closed ' + byStatus.closed.length +
    ' | partial ' + byStatus.partial.length +
    ' | open ' + byStatus.open.length +
    ' | regressed ' + byStatus.regressed.length
)

phase('Critique')
const critique = await agent(
  [
    HOUSE,
    '',
    'Status of the ten assessment findings against current HEAD:',
    JSON.stringify(results, null, 2),
    '',
    'Task, in two parts.',
    '',
    'First: sanity-check this set. Is any status generous given its evidence? Is there a finding',
    'where the fix plausibly introduced a new problem the check would not have thought to look for?',
    '',
    'Second, and more important: what is NOT on this list? The original assessment was one pass by',
    'one reader. Look for defects of the same CLASS as those already found, since that is where',
    'they cluster -- a capability declared but not implemented; a claim in the README the code does',
    'not support; a security property asserted in SECURITY.md that does not hold; a test that',
    'verifies the implementation rather than the requirement. This project has a documented history',
    'of exactly these, and every one was found by looking rather than by waiting.',
    '',
    'Return an updated status summary plus any new findings, each with evidence. Do not edit',
    'anything.',
  ].join('\n'),
  { label: 'critique:completeness', phase: 'Critique', effort: 'high' }
)

return {
  results,
  summary: byStatus,
  clean:
    byStatus.open.length === 0 &&
    byStatus.partial.length === 0 &&
    byStatus.regressed.length === 0,
  critique,
}
