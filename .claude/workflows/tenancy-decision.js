export const meta = {
  name: 'tenancy-decision',
  description: 'Decide the multi-tenancy question deliberately instead of inheriting a day-one non-goal',
  whenToUse:
    'Finding F-09. There is no tenant concept in the data model. The only record of that choice is docs/LIAISON_PROJECT_BRIEF.md, dated the first day of the project, which lists multi-tenant SaaS as a non-goal, points at a stale path, and calls this a prototype. This workflow produces a decision and an ADR. It writes no application code.',
  phases: [
    { title: 'Ground', detail: 'what the schema and audit design already assume' },
    { title: 'Propose', detail: 'four independent positions, argued properly' },
    { title: 'Judge', detail: 'three judges on different criteria' },
    { title: 'Record', detail: 'write the ADR and correct the stale brief' },
  ],
}

const REPO = (args && args.repo) || '/home/iconbaypark2900/secure_ai_data_governance_control_plane'

const HOUSE = [
  'You are working in ' + REPO + ' -- a policy decision point for AI systems.',
  '',
  'This workflow produces a DECISION and an ADR. Do not write application code, do not migrate the',
  'schema, do not commit. The output is an argument the maintainer can act on or reject.',
  '',
  'The ADR voice in docs/adr/ is specific: it states what was believed, what was measured or',
  'observed, and what changed. It argues rather than asserts, and records being wrong. Match it.',
  'Commits, if any, carry NO Co-Authored-By, Claude-Session, or AI trailer.',
].join('\n')

const CONTEXT = [
  'Relevant facts:',
  '- No tenant, org or workspace concept exists anywhere in control_plane/models/.',
  '- control_plane/audit/service.py:156 already anticipates it: the stream parameter overrides',
  '  chain partitioning and the docstring names a tenant as an example of what to pass. ADR 0014',
  '  established that the log is many chains rather than one, partitioned by actor.',
  '- API keys carry coarse scopes (decide, catalog:read/write, policy:read/write, audit:read,',
  '  approvals, detokenize, admin) with no notion of what subset of data a key may reach.',
  '- The catalog resolves resource URNs through pattern registrations, so pg://clinical.* covers',
  '  a whole schema. Any tenancy model has to interact with that coherently.',
  '- CP_TOKENIZATION_KEY and CP_AUDIT_HMAC_KEY are process-wide. Whether tenants share them is a',
  '  real question with real consequences: a shared deterministic tokenisation key means the same',
  '  value tokenises identically across tenants, which leaks equality across a boundary that is',
  '  supposed to be opaque.',
  '- The project is pre-release at 0.1.0 with no deployments, so this is the cheapest it will',
  '  ever be to change.',
].join('\n')

const POSITION_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['position', 'argument', 'schemaImpact', 'keyIsolation', 'costNow', 'costLater', 'whoThisServes'],
  properties: {
    position: { type: 'string' },
    argument: { type: 'string' },
    schemaImpact: { type: 'string' },
    keyIsolation: { type: 'string', description: 'what happens to the audit and tokenisation keys' },
    costNow: { type: 'string' },
    costLater: { type: 'string', description: 'cost of adopting this after a deployment exists' },
    whoThisServes: { type: 'string' },
  },
}

const SCORE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['ranking', 'reasoning'],
  properties: {
    ranking: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['position', 'score', 'why'],
        properties: {
          position: { type: 'string' },
          score: { type: 'number' },
          why: { type: 'string' },
        },
      },
    },
    reasoning: { type: 'string' },
  },
}

phase('Ground')
const ground = await agent(
  [
    HOUSE,
    '',
    CONTEXT,
    '',
    'Task: establish what the codebase already assumes about tenancy, without proposing anything.',
    '',
    'Read control_plane/models/, the audit package, the catalog service, the auth package and the',
    'policy store. Answer concretely: which tables would need a tenant discriminator; where does the',
    'code assume a single global policy set; what does the audit stream partitioning already give',
    'you for free; what would isolation of the two keys actually require; and where would a missing',
    'tenant filter be a silent data leak rather than a visible error.',
    '',
    'That last question matters most. Enumerate every query that would return another tenant data',
    'if a filter were forgotten. Do not edit anything.',
  ].join('\n'),
  { label: 'ground:schema', phase: 'Ground', effort: 'high' }
)

phase('Propose')
const POSITIONS = [
  {
    key: 'single-tenant-forever',
    brief:
      'Argue the day-one non-goal was right and should be affirmed rather than merely inherited. ' +
      'One deployment per boundary, isolation by infrastructure. Make the strongest version of this ' +
      'case: operational simplicity, no cross-tenant leak surface at all, no shared key problem, ' +
      'and a security argument that a shared process is the wrong boundary for a component holding ' +
      'keys that seal an audit log. Say what the README should state so the choice is explicit.',
  },
  {
    key: 'tenant-column',
    brief:
      'Argue for a tenant discriminator on the core tables now, while it is cheap and nothing is ' +
      'deployed. Address the leak surface the grounding agent enumerated -- how do you make a ' +
      'forgotten filter impossible rather than merely unlikely? Consider row-level security in ' +
      'Postgres, a session-scoped setting, or a query layer that cannot express an unfiltered read. ' +
      'Be specific about the keys.',
  },
  {
    key: 'business-unit-lite',
    brief:
      'Argue for the middle position: not SaaS multi-tenancy, but per-business-unit scoping inside ' +
      'one deployment, which is what a platform team at a regulated company actually needs. ' +
      'Policies, catalog and audit streams scoped to a unit; keys still shared because the trust ' +
      'boundary is the company, not the unit. Argue this serves the realistic adopter identified in ' +
      'the market assessment -- an internal platform team -- better than either extreme.',
  },
  {
    key: 'scope-based',
    brief:
      'Argue tenancy is really an authorisation question that the existing scope model should ' +
      'answer, rather than a schema question. Extend API key scopes to carry a resource ' +
      'constraint, so a key can only decide about URNs matching a pattern. Argue this reuses the ' +
      'catalog pattern resolution that already exists and avoids a schema migration entirely -- ' +
      'then be honest about where it fails, particularly for the audit log and for policy authorship.',
  },
]

const positions = (
  await parallel(
    POSITIONS.map((p) => () =>
      agent(
        [
          HOUSE,
          '',
          CONTEXT,
          '',
          'Grounding analysis from a prior agent:',
          ground || '(unavailable -- re-derive)',
          '',
          'Your assigned position: ' + p.key,
          p.brief,
          '',
          'Argue it properly and in good faith, including its weaknesses -- a position defended by',
          'ignoring its costs is useless to the decision. Do not edit anything.',
        ].join('\n'),
        { label: 'propose:' + p.key, phase: 'Propose', schema: POSITION_SCHEMA }
      )
    )
  )
).filter(Boolean)

phase('Judge')
const CRITERIA = [
  {
    key: 'security',
    brief:
      'Judge on isolation strength. Which position makes a cross-tenant leak structurally ' +
      'impossible rather than merely unlikely? Weigh the deterministic tokenisation key problem ' +
      'heavily: a shared key means identical values produce identical tokens across tenants, which ' +
      'leaks equality across the boundary. ADR 0009 accepts that leak within a trust boundary; ' +
      'across one it may be disqualifying.',
  },
  {
    key: 'adoption',
    brief:
      'Judge on who actually deploys this. The realistic adopter is a platform or data-security ' +
      'team at a regulated mid-size company building internally -- not a SaaS vendor and not a ' +
      'procurement-driven enterprise. Which position serves that reader? Which creates work they ' +
      'do not need? Do not optimise for a hypothetical SaaS business that does not exist.',
  },
  {
    key: 'reversibility',
    brief:
      'Judge on cost of being wrong. The project is pre-release with no deployments. Which choice ' +
      'is cheapest to reverse later, and which one becomes permanent the moment someone deploys? ' +
      'Weight heavily toward the option that keeps the decision open, unless another option is ' +
      'clearly better on the merits.',
  },
]

const scores = (
  await parallel(
    CRITERIA.map((c) => () =>
      agent(
        [
          HOUSE,
          '',
          CONTEXT,
          '',
          'Four positions were argued independently:',
          JSON.stringify(positions, null, 2),
          '',
          'Judge them on ONE criterion only: ' + c.key,
          c.brief,
          '',
          'Score each 0-10 on your criterion alone. Do not try to be balanced -- other judges cover',
          'the other criteria, and a judge who hedges across all of them adds nothing.',
        ].join('\n'),
        { label: 'judge:' + c.key, phase: 'Judge', schema: SCORE_SCHEMA }
      )
    )
  )
).filter(Boolean)

phase('Record')
const adr = await agent(
  [
    HOUSE,
    '',
    CONTEXT,
    '',
    'Grounding:',
    ground || '(unavailable)',
    '',
    'Positions:',
    JSON.stringify(positions, null, 2),
    '',
    'Judge scores:',
    JSON.stringify(scores, null, 2),
    '',
    'Task: reach a decision and record it.',
    '',
    'Write docs/adr/0017-multi-tenancy.md (renumber if 0017 is taken) in the established ADR voice.',
    'It must state what was believed at the start, what the code turned out to already assume, what',
    'the judges disagreed about, and what is now decided. Where judges conflicted, say so and say',
    'which criterion won -- an ADR that presents a contested call as obvious is not useful later.',
    '',
    'Also:',
    '- Add the decision to the README, in the "What this is not" section if the answer is',
    '  single-tenant, so the choice is explicit rather than inherited.',
    '- Fix or delete docs/LIAISON_PROJECT_BRIEF.md. It is dated the first day of the project, calls',
    '  this a prototype, points at a stale ~/dataScience/ path, and is now the only written record',
    '  of a decision it was never really making. Whichever way the decision goes, that file should',
    '  not be the place it lives.',
    '',
    'Write no application code and no migration. Do not commit.',
  ].join('\n'),
  { label: 'record:adr', phase: 'Record', effort: 'high' }
)

return { ground, positions, scores, adr }
