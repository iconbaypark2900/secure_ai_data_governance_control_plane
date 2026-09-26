export const meta = {
  name: 'close-redact-discharge',
  description: 'Close the redact silent-discharge hole and the prose regressions the F-01 fix introduced',
  whenToUse: 'Follow-up to fix-obligation-gap (run wf_e7c9ffb8-1a5). That fix closed F-01 for annotate/log/ttl, but three of four adversaries found the same defect class surviving on redact, plus two overclaims the fix itself introduced by folding an inert obligation note into policy prose. Run against the dirty tree that fix produced.',
  phases: [
    { title: 'Reproduce', detail: 'independently confirm the three carried-over defects' },
    { title: 'Decide', detail: 'three proposals on representing a conditionally-unexecuted duty' },
    { title: 'Implement', detail: 'apply, including the seed regression and the ADR correction' },
    { title: 'Verify', detail: 'four adversaries, one hunting specifically for a new prose regression' },
  ],
}

const REPO = (args && args.repo) || '/home/iconbaypark2900/secure_ai_data_governance_control_plane'

const HOUSE = [
  'You are working in ' + REPO + ' -- a policy decision point for AI systems.',
  '',
  'The working tree is DIRTY and that is expected: it carries the F-01 fix (17 files modified, plus',
  'docs/adr/0017-the-control-plane-executes-one-obligation.md and',
  'scripts/check_removed_obligations.py). HEAD is 700db9a. "make check" currently passes: 682 tests,',
  'ruff clean, mypy clean. Build on this tree; do not revert it and do not commit.',
  '',
  'House rules:',
  '- "make check" is the gate. Leave it green.',
  '- ruff line-length 100, py312. mypy disallow_untyped_defs on control_plane/.',
  '- Fail closed. Deny by default.',
  '- ADR 0006: sensitive values never reach durable storage.',
  '- ADR 0010, as amended by 0017: declare only what is implemented. A CONTROL_PLANE entry must be',
  '  a type the decision pipeline actually executes.',
  '- Commits carry NO Co-Authored-By, Claude-Session, or any AI/assistant trailer. Do not commit.',
].join('\n')

const CONTEXT = [
  'What the F-01 fix did: deleted annotate, log and ttl from OBLIGATION_SPECS entirely rather than',
  'reclassifying them to ENFORCEMENT_POINT. The judge rejected reclassification on a measurement --',
  'seed/policies.yaml attached log to the agent read path and pep/mcp_proxy/main.py calls',
  'cp.enforcing() with no can_satisfy set, so reclassifying would have denied every governed tool',
  'call. CONTROL_PLANE_OBLIGATIONS is now exactly {"redact"}.',
  '',
  'Three adversaries then found the defect class surviving. Their evidence, which you should',
  'reproduce rather than trust:',
  '',
  'DEFECT A -- redact is conditionally unexecuted and unconditionally reported discharged.',
  '  pdp.py:292 calls _apply_redactions only when request.options.apply_obligations is true, and',
  '  _apply_redactions itself returns None when payload is None, when there are no redact',
  '  obligations, or when there are no findings (pdp.py:302-312). pdp.py:248 skips scanning',
  '  entirely when scan_payload is false. So in four ordinary request shapes -- no payload,',
  '  scan_payload=False, apply_obligations=False, and a min_confidence that filters every finding --',
  '  the server returns effect=allow, obligations=[redact], unsupported_obligations=[],',
  '  redactions=[], and in two of them the payload verbatim with the email in cleartext.',
  '  Both SDKs hold SATISFIED_BY_CONTROL_PLANE = {"redact"} as a STATIC set consulted with no',
  '  reference to the request, so outstanding() returns [] and enforce() hands back the unredacted',
  '  string. Worse, client.py:559-561 and client.ts:241,272 then report outcome=enforced with',
  '  discharged=["redact"], writing a false discharge into the decision record for a redaction the',
  '  plane provably declined to perform. That is the route-on-the-response-path shape from commit',
  '  235b221 exactly.',
  '',
  'DEFECT B -- pdp.py:284 blanks the whole unsupported list on an authorization-only decision.',
  '  unsupported_obligations=unsupported if request.options.apply_obligations else []. Proven with',
  '  a watermark obligation: ["watermark"] with apply=True, [] with apply=False, same policy and',
  '  principal. The F-01 fix narrowed SELF_EXECUTABLE, the first half of that expression, and left',
  '  the second. Both reference SDKs are insulated only because they ignore the field and recompute',
  '  from obligations -- which means nothing in the suite can notice when it is wrong, and a',
  '  non-SDK enforcement point reading it is told its watermark duty is clear.',
  '',
  'DEFECT C -- the fix moved two unimplemented claims from a checkable place into prose.',
  '  It deleted "- type: annotate / note: de-identified before leaving the boundary" from',
  '  allow-agents-external-inference-scrubbed and folded that note into the policy description as an',
  '  assertion of fact. The description now claims what leaves the boundary is de-identified, while',
  '  the only obligation is redact labels:[pii, pci] strategy:hash, which covers no phi.* label. A',
  '  live run returns allow with MRN 4827193, NPI 1245319599 and E11.9 in the clear and',
  '  unsupported_obligations=[]. deny-phi-to-external-models does not rescue it because it selects',
  '  on resource.classifications, not payload findings.',
  '  Second instance, also introduced: allow-analysts-read-unredacted now claims the decision record',
  '  and audit event happen on every decision unless options.persist is false. The fail-closed',
  '  except path at pdp.py:169-181 returns before the persist block at pdp.py:195, so a',
  '  pipeline-error decision persists nothing at persist=True.',
  '  Third, pre-existing: allow-agents-read-redacted claims the agent may not learn who the records',
  '  are about; an ordinary read returns street address, DOB and MRN untouched.',
  '  tests/integration/test_seed_policies.py opens by saying the shipped set must behave as its',
  '  descriptions claim, but every assertion in it is set membership over obligation TYPES. No test',
  '  in the file reads a description field. All 23 pass and cannot see any of this.',
  '',
  'DEFECT D -- ADR 0017:183-185 misstates its own measurement, saying the server returns an empty',
  '  obligation list when the field actually emptied is unsupported_obligations. The obligations',
  '  list is built unconditionally. An ADR whose rule is to state what was measured got its one',
  '  measurement of the residual hole wrong, in the direction that makes the hole sound smaller.',
  '',
  'DEFECT E -- sdk/typescript/package.json declares files:["dist"] and main:./dist/index.js with no',
  '  prepublishOnly or prepack. dist/types.js still carries the old permissive set, so npm publish',
  '  from this checkout ships a client that silently discharges annotate, log and ttl.',
].join('\n')

const REPRO_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['defect', 'confirmed', 'evidence', 'corrections'],
  properties: {
    defect: { type: 'string' },
    confirmed: { type: 'boolean' },
    evidence: { type: 'string', description: 'output you produced yourself' },
    corrections: {
      type: 'array',
      items: { type: 'string' },
      description: 'anything the adversary got wrong, overstated, or missed',
    },
  },
}

const PROPOSAL_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['approach', 'rationale', 'serverChange', 'sdkChange', 'breaks', 'risks'],
  properties: {
    approach: { type: 'string' },
    rationale: { type: 'string' },
    serverChange: { type: 'string' },
    sdkChange: { type: 'string' },
    breaks: { type: 'array', items: { type: 'string' }, description: 'what existing behaviour changes' },
    risks: { type: 'array', items: { type: 'string' } },
  },
}

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['stillOpen', 'evidence', 'detail'],
  properties: {
    stillOpen: { type: 'boolean' },
    evidence: { type: 'string' },
    detail: { type: 'string' },
  },
}

phase('Reproduce')
const DEFECTS = [
  { key: 'A-redact-discharge', focus: 'Defect A. Drive the real PDP in all four request shapes and both SDKs. Confirm or refute each leg separately, including the false discharge written back through report_outcome.' },
  { key: 'B-unsupported-blanked', focus: 'Defect B. Confirm pdp.py:284 blanks the list, and establish what a non-SDK enforcement point would actually see. Check whether either PEP in this repo reads the field.' },
  { key: 'C-prose-regression', focus: 'Defects C and D. Run the seed policies against their own descriptions by hand. Confirm each of the three claims, check the ADR 0017 measurement, and read the full git diff of seed/policies.yaml to find any other claim the fix moved into prose.' },
]

const repros = (
  await parallel(
    DEFECTS.map((d) => () =>
      agent(
        [
          HOUSE,
          '',
          CONTEXT,
          '',
          'Independently reproduce, do not trust the report. A prior adversary claimed these; your',
          'job is to confirm them with your own evidence or refute them. Report confirmed=false if',
          'the claim does not hold, and record anything overstated in "corrections" -- an inflated',
          'finding wastes the fix.',
          '',
          'Your defect: ' + d.key,
          d.focus,
          '',
          'Do not edit anything.',
        ].join('\n'),
        { label: 'repro:' + d.key, phase: 'Reproduce', schema: REPRO_SCHEMA, effort: 'high' }
      )
    )
  )
).filter(Boolean)

log(repros.filter((r) => r.confirmed).length + '/' + repros.length + ' defects confirmed on reproduction')

phase('Decide')
const ANGLES = [
  { key: 'server-truthful', brief: 'Argue the server should tell the truth: when _apply_redactions does not run or returns None, redact belongs in unsupported_obligations, and unsupported should be reported regardless of apply_obligations. The SDKs then need no change because they already refuse on a populated unsupported set -- except they do not read that field, so address that too. Favour making the wire response correct over patching clients.' },
  { key: 'client-conditional', brief: 'Argue SATISFIED_BY_CONTROL_PLANE cannot be a static set, because whether the plane discharged redact is a property of the response rather than of the type. Make outstanding() consult evidence -- redactions present, payload returned -- in both SDKs, and make the discharge report follow. Consider that this must work against an older server.' },
  { key: 'refuse-the-shape', brief: 'Argue the real defect is that the request shape is incoherent and should be rejected: asking for a decision with apply_obligations=False or scan_payload=False on a policy set that attaches redact is asking the plane to permit something it cannot make safe. Fail closed at the API boundary rather than returning a half-honoured allow. Be honest about which legitimate callers this breaks -- the MCP proxy calls with apply_obligations=False.' },
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
          'Reproduction results:',
          JSON.stringify(repros, null, 2),
          '',
          'Your angle: ' + a.key,
          a.brief,
          '',
          'Check what actually calls the PDP with these options before you argue -- pep/mcp_proxy,',
          'pep/reverse_proxy, the console, the CLI and the simulate endpoint all have opinions.',
          'Enumerate what your approach breaks. Do not edit anything.',
        ].join('\n'),
        { label: 'propose:' + a.key, phase: 'Decide', schema: PROPOSAL_SCHEMA, effort: 'high' }
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
    'Reproduction:',
    JSON.stringify(repros, null, 2),
    '',
    'Three proposals:',
    JSON.stringify(proposals, null, 2),
    '',
    'Choose and write the implementation brief, grafting freely.',
    '',
    'Deciding criterion, in order: (1) an enforcement point must never be told a duty is clear when',
    'nothing discharged it; (2) no legitimate existing caller starts denying -- verify against',
    'pep/mcp_proxy and pep/reverse_proxy specifically, since that measurement is what redirected the',
    'previous fix; (3) prefer making the server response correct over compensating in clients,',
    'because a non-SDK enforcement point reads only the wire.',
    '',
    'The brief must also cover the prose regressions (defect C), the ADR 0017 correction (D), and',
    'the npm packaging hole (E). Do not edit anything.',
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
    brief,
    '',
    'Requirements:',
    '- Fix defects A through E.',
    '- For defect C, do NOT repeat the mistake that caused it. The previous fix deleted an inert',
    '  obligation and asserted its content as prose. Either make the policy actually do what its',
    '  description says -- add phi to the redact labels and re-verify the MRN/NPI/ICD-10 case -- or',
    '  cut the description back to what the obligation demonstrably does. Do not write a claim you',
    '  have not measured.',
    '- Add the guard that would have caught C: tests/integration/test_seed_policies.py must assert',
    '  BEHAVIOUR against descriptions, not set membership over obligation types. At minimum, every',
    '  policy whose description claims an identifier class does not leave must be driven through the',
    '  PDP with a payload containing that class, and the output checked.',
    '- Extend the new guard at tests/integration/test_pdp.py over the request-shape axis:',
    '  scan_payload=False, apply_obligations=False, payload absent, and a filtering min_confidence.',
    '  That axis is the one the previous fix left uncovered.',
    '- Correct ADR 0017 to say what was actually measured, and name all four request shapes.',
    '- Run "make check" and leave it green. Run the TypeScript tests too.',
    '',
    'Do not commit. Leave the working tree dirty for review.',
  ].join('\n'),
  { label: 'implement', phase: 'Implement', effort: 'high' }
)

phase('Verify')
const LENSES = [
  { key: 'silent-discharge', probe: 'Try to obtain an allow where a duty went undischarged and the caller was told otherwise. Sweep the request-option space -- apply_obligations, scan_payload, min_confidence, explain, persist, payload absent, payload past CP_MAX_SCAN_CHARS, structured versus string payloads -- against policies carrying redact and against policies carrying enforcement-point obligations. Check what report_outcome writes back in each case.' },
  { key: 'new-prose-regression', probe: 'You are hunting specifically for the failure the previous fix committed: a claim moved from somewhere checkable into somewhere unchecked. Read the FULL diff of this change against the F-01 tree. For every sentence added or altered in seed/policies.yaml, README.md, docs/ and the ADRs, ask whether it asserts behaviour, and if so drive that behaviour through the real PDP. Report any sentence you cannot make true by measurement.' },
  { key: 'no-new-denials', probe: 'Confirm no legitimate caller started denying. Run the full test suite, the TypeScript suite, and the two enforcement points against their integration tests. Then drive the MCP proxy and the reverse proxy end to end against the shipped seed policy set and confirm governed traffic still flows. A fix that closes the hole by denying everything is not a fix, and this is exactly how the previous approach was rejected.' },
  { key: 'wire-contract', probe: 'You are a non-SDK enforcement point that reads only the HTTP response. Is the wire response now sufficient to know exactly which duties are outstanding, in every request shape? Check the OpenAPI schema, the response model, and the generated SDK contract fixture agree with each other and with reality. Regenerate the fixture and confirm CI would pass.' },
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
          'A follow-up fix has been applied on top of the F-01 tree. Summary:',
          applied || '(unavailable -- inspect with git diff)',
          '',
          'You are an adversary. Default to stillOpen=true unless you demonstrated otherwise. The',
          'previous round of this workflow was cleared by one lens and broken by three, and two of',
          'those three found problems the fix itself introduced. Assume the same is possible here.',
          '',
          'Your lens: ' + l.key,
          l.probe,
        ].join('\n'),
        { label: 'verify:' + l.key, phase: 'Verify', schema: VERDICT_SCHEMA, effort: 'high' }
      )
    )
  )
).filter(Boolean)

const open = verdicts.filter((v) => v.stillOpen)
log(open.length ? open.length + '/' + verdicts.length + ' lenses say still open' : 'all lenses clear')

return { repros, proposals, brief, applied, verdicts, stillOpen: open, clean: open.length === 0 }
