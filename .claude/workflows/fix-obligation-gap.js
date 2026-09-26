export const meta = {
  name: 'fix-obligation-gap',
  description: 'Close the annotate/log/ttl obligation gap and adversarially verify it stays closed',
  whenToUse:
    'Finding F-01. Three obligation types are declared Executor.CONTROL_PLANE, are therefore excluded from unsupported_obligations and reported discharged by both SDKs, and are executed by nothing. The shipped reference policy set uses one of them.',
  phases: [
    { title: 'Map', detail: 'trace every path that touches annotate / log / ttl' },
    { title: 'Decide', detail: 'three independent proposals, then a judge' },
    { title: 'Implement', detail: 'apply the chosen approach' },
    { title: 'Verify', detail: 'four adversaries, each trying to show the gap is still open' },
  ],
}

const REPO = (args && args.repo) || '/home/iconbaypark2900/secure_ai_data_governance_control_plane'

const HOUSE = [
  'You are working in ' + REPO + ' -- a policy decision point for AI systems, split PDP/PEP.',
  '',
  'House rules, taken from the codebase own standards:',
  '- "make check" is the gate: ruff check, ruff format --check, mypy on control_plane/, pytest.',
  '  682 tests pass in about 14s on SQLite. Do not leave them failing.',
  '- ruff line-length 100, target py312. mypy disallow_untyped_defs on control_plane/.',
  '- Fail closed. Deny by default. An error on the decision path is a deny, never an allow.',
  '- ADR 0006: sensitive values never reach durable storage.',
  '- ADR 0010: declare only what is implemented. This finding is a violation of that ADR.',
  '- Load-bearing decisions get an ADR in docs/adr/, numbered from 0017, in the existing voice:',
  '  state what was believed, what was measured, and what changed. Argue, do not assert.',
  '- Commits must carry NO Co-Authored-By, Claude-Session, or any AI/assistant trailer.',
].join('\n')

const CONTEXT = [
  'The defect, already traced:',
  '- control_plane/policy/model.py:110-122 declares annotate, log and ttl as Executor.CONTROL_PLANE.',
  '- model.py:156 derives CONTROL_PLANE_OBLIGATIONS from that executor field.',
  '- pdp.py:76 sets SELF_EXECUTABLE = CONTROL_PLANE_OBLIGATIONS.',
  '- pdp.py:264 excludes SELF_EXECUTABLE types from unsupported_obligations, so an enforcement',
  '  point is told nothing is outstanding.',
  '- sdk/python/control_plane_sdk/client.py:50 lists all three in SATISFIED_BY_CONTROL_PLANE, so',
  '  decision.enforce() will not raise for them. The TypeScript SDK mirrors this.',
  '- pdp.py:294-314 _apply_obligations filters for type == "redact" and nothing else.',
  '- Nothing anywhere reads annotate, log or ttl.',
  '- seed/policies.yaml:265 uses "- type: annotate", so the shipped reference set makes a claim',
  '  that is not true.',
  '',
  'This is structurally the same bug as the route-on-the-response-path defect fixed in commit',
  '235b221, where an enforcement point declared it could satisfy an obligation that had nothing',
  'left to act on.',
].join('\n')

const PROPOSAL_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['approach', 'rationale', 'changes', 'risks', 'adrNeeded'],
  properties: {
    approach: {
      type: 'string',
      enum: ['reclassify', 'implement', 'split'],
      description:
        'reclassify = move all three to Executor.ENFORCEMENT_POINT so enforce() raises. ' +
        'implement = make the control plane actually discharge them. ' +
        'split = different answer per obligation type.',
    },
    rationale: { type: 'string' },
    changes: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['file', 'change'],
        properties: { file: { type: 'string' }, change: { type: 'string' } },
      },
    },
    risks: { type: 'array', items: { type: 'string' } },
    adrNeeded: { type: 'boolean' },
  },
}

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['gapStillOpen', 'evidence', 'detail'],
  properties: {
    gapStillOpen: { type: 'boolean' },
    evidence: { type: 'string', description: 'file:line or command output supporting the verdict' },
    detail: { type: 'string' },
  },
}

phase('Map')
const map = await agent(
  [
    HOUSE,
    '',
    CONTEXT,
    '',
    'Task: read the code and produce an exhaustive map of every site that reads, writes, derives',
    'from, validates, documents or tests the annotate, log and ttl obligation types. Include the',
    'Python SDK, the TypeScript SDK, the two enforcement points under pep/, the console under ui/,',
    'seed/policies.yaml, docs/, README.md, and the test suite.',
    '',
    'For each site say what it does with the type and whether it would need to change under a',
    'reclassify approach, an implement approach, or both. Do not edit anything.',
  ].join('\n'),
  { label: 'map:call-sites', phase: 'Map' }
)

phase('Decide')
const ANGLES = [
  {
    key: 'minimal-honesty',
    brief:
      'Argue for the smallest change that makes the system stop lying. Weigh that ADR 0010 ' +
      'already committed the project to declaring only what is implemented, and that the ' +
      'maintainer removed notify and route once before for exactly this reason.',
  },
  {
    key: 'operator-value',
    brief:
      'Argue from what an operator actually needs. Is a ttl obligation that bounds downstream ' +
      'retention worth building? Is annotate worth a decision-record column? Is log worth a ' +
      'structlog level bump? Judge each on whether anyone would use it, not on tidiness.',
  },
  {
    key: 'contract-integrity',
    brief:
      'Argue from the wire contract between the control plane and its two SDKs. Which approach ' +
      'keeps the Python and TypeScript clients honest and in agreement, and which one is most ' +
      'likely to drift again? Consider tools/generate_sdk_contract.py and the CI check on it.',
  },
]

const proposals = (
  await parallel(
    ANGLES.map((a) => () =>
      agent(
        [
          HOUSE,
          '',
          CONTEXT,
          '',
          'Call-site map from a prior agent:',
          map || '(map unavailable -- re-derive it yourself)',
          '',
          'Your assigned angle: ' + a.key,
          a.brief,
          '',
          'Propose one approach. Be concrete about files and changes. Do not edit anything.',
        ].join('\n'),
        { label: 'propose:' + a.key, phase: 'Decide', schema: PROPOSAL_SCHEMA }
      )
    )
  )
).filter(Boolean)

log(proposals.length + ' proposals: ' + proposals.map((p) => p.approach).join(', '))

const decision = await agent(
  [
    HOUSE,
    '',
    CONTEXT,
    '',
    'Three independent proposals follow. Pick one approach and write the implementation brief.',
    'You may graft the best parts of the runners-up. Prefer the option that leaves the system',
    'unable to make a false claim, even if it removes capability -- that is the precedent the',
    'project already set when it cut notify and route.',
    '',
    JSON.stringify(proposals, null, 2),
    '',
    'Return a precise implementation brief: files, edits, tests to add, and whether an ADR is',
    'warranted. Do not edit anything.',
  ].join('\n'),
  { label: 'judge:approach', phase: 'Decide', effort: 'high' }
)

phase('Implement')
const applied = await agent(
  [
    HOUSE,
    '',
    CONTEXT,
    '',
    'Implementation brief, already decided. Follow it.',
    decision,
    '',
    'Apply the change. Then:',
    '- Add or update tests so the gap cannot silently reopen. At minimum there must be a test that',
    '  fails if an obligation type is declared CONTROL_PLANE while no code path executes it.',
    '- Run "make check" and leave it green.',
    '- Run "cpctl policy validate seed/policies.yaml" and fix seed/policies.yaml if the change',
    '  invalidates the annotate obligation it uses at line 265.',
    '- Update README.md where it describes the seven obligation types and their executors, and',
    '  update docs/policy-language.md to match. Keep the existing prose voice.',
    '- Write the ADR if the brief calls for one.',
    '',
    'Do not commit. Leave the working tree dirty for review.',
  ].join('\n'),
  { label: 'implement', phase: 'Implement', effort: 'high' }
)

phase('Verify')
const LENSES = [
  {
    key: 'enforce-raises',
    probe:
      'Write and run a throwaway script against the modified code proving that a decision ' +
      'carrying each of annotate, log and ttl either (a) causes decision.enforce() to raise when ' +
      'the caller has not declared it can satisfy them, or (b) demonstrably performs the duty. ' +
      'If neither holds for any of the three, the gap is still open.',
  },
  {
    key: 'sdk-parity',
    probe:
      'Check the TypeScript SDK and the generated contract fixture. If the Python side changed ' +
      'and sdk/typescript did not, the two clients now disagree and the gap is still open on the ' +
      'JS path. Run the TypeScript tests and tools/generate_sdk_contract.py.',
  },
  {
    key: 'seed-truthfulness',
    probe:
      'Read seed/policies.yaml end to end and every policy description in it. Does any policy ' +
      'still promise an effect the code does not produce? Run the integration test that checks ' +
      'the shipped policy set against its own descriptions.',
  },
  {
    key: 'docs-truthfulness',
    probe:
      'Read README.md, docs/policy-language.md, docs/architecture.md and docs/adr/0010. Does any ' +
      'of them still claim the control plane executes something it does not? Quote any sentence ' +
      'that is now false.',
  },
]

const verdicts = (
  await parallel(
    LENSES.map((l) => () =>
      agent(
        [
          HOUSE,
          '',
          CONTEXT,
          '',
          'A fix has been applied. Summary of what was done:',
          applied || '(summary unavailable -- inspect the working tree with git diff)',
          '',
          'You are an adversary. Your job is to show the gap is STILL OPEN, not to confirm the fix.',
          'Default to gapStillOpen=true if you cannot prove otherwise.',
          '',
          'Your lens: ' + l.key,
          l.probe,
        ].join('\n'),
        { label: 'verify:' + l.key, phase: 'Verify', schema: VERDICT_SCHEMA, effort: 'high' }
      )
    )
  )
).filter(Boolean)

const open = verdicts.filter((v) => v.gapStillOpen)
log(open.length ? open.length + ' lens(es) say the gap is still open' : 'all lenses clear')

return {
  approach: proposals.map((p) => p.approach),
  brief: decision,
  applied,
  verdicts,
  stillOpen: open,
  clean: open.length === 0,
}
