export const meta = {
  name: 'policy-replay',
  description: 'Replay a candidate policy set against recorded decisions, and be honest about what it cannot reproduce',
  whenToUse:
    "Finding F-07. /v1/simulate diffs a candidate policy set against the baseline for ONE request. The question that makes a policy change safe to ship is what it would have done to last week's traffic, and nothing answers that.",
  phases: [
    { title: 'Fidelity', detail: 'establish exactly what a replay can and cannot faithfully reproduce' },
    { title: 'Design', detail: 'three approaches to the fidelity problem, then a judge' },
    { title: 'Implement', detail: 'build the replay path' },
    { title: 'Verify', detail: 'prove it agrees with live evaluation, and that it never overclaims' },
  ],
}

const REPO = (args && args.repo) || '/home/iconbaypark2900/secure_ai_data_governance_control_plane'

const HOUSE = [
  'You are working in ' + REPO + ' -- a policy decision point for AI systems.',
  '',
  'House rules:',
  '- "make check" is the gate: ruff, mypy on control_plane/, pytest. 682 tests pass in ~14s.',
  '- ruff line-length 100, py312. mypy disallow_untyped_defs on control_plane/.',
  '- ADR 0006 is not negotiable: payload content is never persisted, and replay must not become a',
  '  reason to start persisting it. If a faithful replay would require the payload, the answer is a',
  '  less faithful replay that says so -- not a weakened ADR.',
  '- ADR 0010: declare only what is implemented. A replay that silently overstates its own accuracy',
  '  is exactly the kind of false claim this project keeps finding and removing.',
  '- Load-bearing decisions get an ADR in docs/adr/, numbered from 0017, in the existing voice.',
  '- Commits carry NO Co-Authored-By, Claude-Session, or any AI/assistant trailer.',
].join('\n')

const CONTEXT = [
  'What exists:',
  '- control_plane/api/v1/decisions.py:83 -- POST /v1/simulate. Evaluates a candidate set and the',
  '  stored set against ONE request, reports whether effect or matched policies differ, persists',
  '  nothing. The console has a Simulator page.',
  '- control_plane/models/decision.py -- DecisionRecord persists: principal_id, principal_type,',
  '  action, resource_urn, resource_kind, effect, reason, determining_policy, matched_policies,',
  '  obligations, classifications, finding_count, redaction_count, payload_digest (keyed, not',
  '  reversible), context, trace, latency_ms, correlation_id, outcome fields.',
  '',
  'The fidelity problem, stated precisely:',
  'The policy engine offers three deliberately distinct label selectors --',
  '  resource.classifications  what the catalog says the store holds',
  '  findings                  what was found in THIS payload',
  '  classifications           the union',
  'The decision record stores the union under "classifications" and a finding COUNT, but not the',
  'individual findings with their labels and offsets. So a replay can faithfully re-evaluate any',
  'rule keyed on principal, action, resource, context or the union -- and cannot faithfully',
  're-evaluate a rule keyed on the findings selector, which is precisely the selector used by the',
  'highest-priority rule in the shipped policy set (deny-credentials-anywhere matches',
  'findings: {any_of: [secret]}).',
  '',
  'That is the crux of this workflow. Everything else is mechanical.',
].join('\n')

const FIDELITY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['reproducible', 'notReproducible', 'storedButUnused', 'recommendation'],
  properties: {
    reproducible: {
      type: 'array',
      items: { type: 'string' },
      description: 'match conditions a replay can evaluate exactly from stored fields',
    },
    notReproducible: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['condition', 'why', 'affectedSeedPolicies'],
        properties: {
          condition: { type: 'string' },
          why: { type: 'string' },
          affectedSeedPolicies: { type: 'array', items: { type: 'string' } },
        },
      },
    },
    storedButUnused: {
      type: 'array',
      items: { type: 'string' },
      description: 'fields already persisted that a replay could exploit but an obvious design would miss',
    },
    recommendation: { type: 'string' },
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

phase('Fidelity')
const fidelity = await agent(
  [
    HOUSE,
    '',
    CONTEXT,
    '',
    'Task: establish the fidelity boundary precisely, before anyone designs anything.',
    '',
    'Read control_plane/policy/operators.py and engine.py and enumerate EVERY match condition the',
    'policy language supports. For each, determine whether it can be evaluated exactly from what',
    'DecisionRecord persists, and if not, why. Then check the shipped policy set in',
    'seed/policies.yaml and say which of its fourteen policies fall on which side of the line.',
    '',
    'Look hard for fields already persisted that a naive design would overlook -- the stored trace',
    'may contain per-policy evaluation detail that reveals what a condition evaluated to, which',
    'would let a replay reconstruct more than the top-level columns suggest. That possibility is',
    'the difference between a useful feature and a misleading one, so establish it properly.',
    '',
    'Do not edit anything.',
  ].join('\n'),
  { label: 'fidelity-boundary', phase: 'Fidelity', schema: FIDELITY_SCHEMA, effort: 'high' }
)

log(
  (fidelity ? fidelity.notReproducible.length : '?') +
    ' condition class(es) cannot be faithfully replayed'
)

phase('Design')
const ANGLES = [
  {
    key: 'honest-partial',
    brief:
      'Design a replay that evaluates what it can and refuses to guess at the rest. Every replayed ' +
      'decision is labelled exact or indeterminate, and the summary reports both counts. Argue that ' +
      'an operator who knows 8,000 decisions replayed exactly and 400 are indeterminate is better ' +
      'served than one given 8,400 confident answers of which 400 are wrong.',
  },
  {
    key: 'bounded-interval',
    brief:
      'Design a replay that reports a RANGE rather than a verdict where evidence is incomplete: ' +
      'given finding_count and the stored union of classifications, compute the best and worst case ' +
      'effect. A decision that is deny under every consistent assumption is genuinely deny. Argue ' +
      'this recovers more signal than labelling those decisions indeterminate, and be specific ' +
      'about when the bound is tight and when it is useless.',
  },
  {
    key: 'forward-capture',
    brief:
      'Argue the fidelity problem should be fixed at the source rather than worked around. What is ' +
      'the minimum addition to DecisionRecord that makes future decisions fully replayable without ' +
      'violating ADR 0006 -- the set of finding LABELS with counts, say, which is metadata rather ' +
      'than content, and is arguably already implied by the stored classifications union. Be ' +
      'rigorous about whether that crosses the ADR 0006 line, since the whole value of this option ' +
      'depends on it not doing so. Historical decisions stay partially replayable; new ones do not.',
  },
]

const designs = (
  await parallel(
    ANGLES.map((a) => () =>
      agent(
        [
          HOUSE,
          '',
          CONTEXT,
          '',
          'Fidelity analysis from a prior agent:',
          JSON.stringify(fidelity, null, 2),
          '',
          'Your assigned angle: ' + a.key,
          a.brief,
          '',
          'Design the CLI surface (cpctl policy replay), the API surface if one is warranted, and',
          'the output an operator actually reads -- effect flips, newly denied principals, newly',
          'allowed ones. Newly ALLOWED is the more dangerous direction and should be hardest to',
          'overlook in the output. Do not edit anything.',
        ].join('\n'),
        { label: 'design:' + a.key, phase: 'Design' }
      )
    )
  )
).filter(Boolean)

const brief = await agent(
  [
    HOUSE,
    '',
    CONTEXT,
    '',
    'Fidelity analysis:',
    JSON.stringify(fidelity, null, 2),
    '',
    'Three designs follow. Choose and write the implementation brief, grafting freely.',
    '',
    designs.join('\n\n---\n\n'),
    '',
    'The deciding criterion: an operator must never be able to read the output and believe the',
    'replay covered a policy it could not evaluate. Prefer the design that makes overclaiming',
    'structurally impossible over the one that merely documents the caveat.',
    '',
    'Do not edit anything.',
  ].join('\n'),
  { label: 'judge:design', phase: 'Design', effort: 'high' }
)

phase('Implement')
const applied = await agent(
  [
    HOUSE,
    '',
    CONTEXT,
    '',
    'Implementation brief, already decided. Follow it.',
    brief,
    '',
    'Requirements:',
    '- Replay reads recorded decisions and never persists anything. It is an analysis tool.',
    '- It must scale to a large decision table without loading it all into memory.',
    '- Anything the replay could not faithfully evaluate is reported as such, prominently.',
    '- Tests: replaying the CURRENT policy set against recorded decisions must reproduce the',
    '  recorded effects exactly for every decision the fidelity analysis said is reproducible. That',
    '  is the correctness contract for this feature -- if it cannot reproduce a decision it already',
    '  made, it cannot predict one it has not.',
    '- Write the ADR covering the fidelity boundary and why it was resolved this way.',
    '- Update README.md and docs/policy-language.md. Keep the existing prose voice.',
    '- Run "make check" and leave it green.',
    '',
    'Do not commit. Leave the working tree dirty for review.',
  ].join('\n'),
  { label: 'implement:replay', phase: 'Implement', effort: 'high' }
)

phase('Verify')
const CHECKS = [
  {
    key: 'self-agreement',
    probe:
      'Seed a database with a few thousand varied decisions across the full seed policy set, then ' +
      'replay the CURRENT policy set against them. Every decision the fidelity analysis called ' +
      'reproducible must come back identical. Any divergence is a bug in the replay, and it is the ' +
      'single most important check here. Report the exact divergence count.',
  },
  {
    key: 'no-overclaim',
    probe:
      'You are trying to make the replay assert something it cannot know. Construct policy sets ' +
      'that hinge entirely on the findings selector, on context keys that were never recorded, and ' +
      'on payload_truncated. Does the output ever present a confident verdict where the evidence ' +
      'does not support one? Read the output as an operator would, not as its author -- a caveat in ' +
      'a footer under a confident headline count is an overclaim.',
  },
  {
    key: 'scale-and-safety',
    probe:
      'Replay against a large table and confirm memory stays bounded and it completes in a sane ' +
      'time. Then confirm it is genuinely read-only: no decision records written, no audit entries ' +
      'sealed, no policy state mutated. A tool operators run against production must not leave a ' +
      'trace in the record it is analysing.',
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
          'Replay has been implemented. Summary:',
          applied || '(unavailable -- inspect with git diff)',
          '',
          'You are an adversary. Default to pass=false unless you demonstrated the property holds.',
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
log(failed.length ? failed.length + ' check(s) failed' : 'all checks passed')

return { fidelity, designs, brief, applied, verdicts, failures: failed, clean: failed.length === 0 }
