export const meta = {
  name: 'identity-attribution',
  description: 'Give the audit chain a human subject: OIDC on the console, real actors on every seal',
  whenToUse:
    'Finding F-02. caller.identity resolves to the API key name, so every sealed admin action is attributed to a shared credential rather than a person. Non-repudiation is unachievable.',
  phases: [
    { title: 'Survey', detail: 'map every actor= call site and the console auth path' },
    { title: 'Design', detail: 'three independent designs, then a judge' },
    { title: 'Implement', detail: 'apply the chosen design' },
    { title: 'Attack', detail: 'four adversaries, each with a distinct bypass lens' },
  ],
}

const REPO = (args && args.repo) || '/home/iconbaypark2900/secure_ai_data_governance_control_plane'

const HOUSE = [
  'You are working in ' + REPO + ' -- a policy decision point for AI systems.',
  '',
  'House rules:',
  '- "make check" is the gate: ruff, mypy on control_plane/, pytest. 682 tests pass in ~14s.',
  '- ruff line-length 100, py312. mypy disallow_untyped_defs on control_plane/.',
  '- Fail closed. Deny by default.',
  '- ADR 0006: sensitive values never reach durable storage.',
  '- ADR 0010: declare only what is implemented.',
  '- Load-bearing decisions get an ADR in docs/adr/, numbered from 0017, in the existing voice.',
  '- Commits carry NO Co-Authored-By, Claude-Session, or any AI/assistant trailer.',
].join('\n')

const CONTEXT = [
  'The defect, already traced:',
  '- control_plane/auth/service.py:40 -- identity returns self.record.name, the API key name.',
  '- Roughly fourteen sites across control_plane/api/v1/*.py seal audit events with',
  '  actor=caller.identity: policy sync, approval grants, detokenize, asset delete, discovery,',
  '  checkpoint, key issue.',
  '- ui/src/lib/api.ts:26 -- the console reads a raw API key from sessionStorage and sends it as',
  '  X-API-Key. There is no OIDC, no per-user identity, and no session lifetime beyond tab close.',
  '',
  'Consequence: the HMAC audit chain proves a record was not altered, but the thing it attests to',
  'is a shared credential. "Who approved this PHI export?" answers with a key name. The',
  'cryptography is sound and what it signs is too weak to carry it.',
  '',
  'Design constraint that must survive: machine enforcement points (pep/reverse_proxy,',
  'pep/mcp_proxy, the SDKs) legitimately authenticate with API keys and have no human subject.',
  'The design must distinguish a machine actor from a human actor rather than forcing one model',
  'onto both, and the audit record must make clear which it was.',
].join('\n')

const DESIGN_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['name', 'summary', 'actorModel', 'consoleAuth', 'migration', 'tradeoffs'],
  properties: {
    name: { type: 'string' },
    summary: { type: 'string' },
    actorModel: {
      type: 'string',
      description: 'how a human subject and a machine key are represented in the audit actor field',
    },
    consoleAuth: { type: 'string', description: 'how the console authenticates a person' },
    migration: { type: 'string', description: 'what happens to audit records already sealed' },
    tradeoffs: { type: 'array', items: { type: 'string' } },
  },
}

const ATTACK_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['bypassed', 'attack', 'evidence'],
  properties: {
    bypassed: { type: 'boolean', description: 'true if you got attribution to be wrong or forgeable' },
    attack: { type: 'string' },
    evidence: { type: 'string' },
  },
}

phase('Survey')
const survey = await agent(
  [
    HOUSE,
    '',
    CONTEXT,
    '',
    'Task: produce an exhaustive survey. List every call site that passes an actor into the audit',
    'service, every place caller.identity or AuthenticatedCaller is constructed, the full console',
    'auth path from ui/src/lib/api.ts through control_plane/api/deps.py, and every audit event type',
    'in control_plane/audit/. For each, say whether the actor is legitimately a machine or should',
    'be a person. Do not edit anything.',
  ].join('\n'),
  { label: 'survey:actors', phase: 'Survey' }
)

phase('Design')
const ANGLES = [
  {
    key: 'oidc-first',
    brief:
      'Design around a standard OIDC integration: the console redirects to an IdP, the API accepts ' +
      'a validated bearer token alongside API keys, and the authenticated subject flows into actor. ' +
      'Favour something a real enterprise IdP (Entra, Okta, Keycloak) supports without custom work.',
  },
  {
    key: 'delegation-chain',
    brief:
      'Design around delegation: the audit record carries both the key that authenticated and the ' +
      'human on whose behalf it acted, so a PEP acting for a user is representable and a shared key ' +
      'acting alone is visibly unattributed. Consider what this does to the chain content digest.',
  },
  {
    key: 'minimal-credible',
    brief:
      'Design the smallest change that makes attribution real, on the assumption the maintainer is ' +
      'one person and cannot run an IdP. What is the least infrastructure that still yields ' +
      'non-repudiation? Consider per-user keys with an owner field, signed operator assertions, or ' +
      'a local user table -- and be honest about which of these actually achieves non-repudiation ' +
      'and which only looks like it does.',
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
          'Survey from a prior agent:',
          survey || '(unavailable -- re-derive)',
          '',
          'Your assigned angle: ' + a.key,
          a.brief,
          '',
          'Produce one design. Do not edit anything.',
        ].join('\n'),
        { label: 'design:' + a.key, phase: 'Design', schema: DESIGN_SCHEMA }
      )
    )
  )
).filter(Boolean)

const chosen = await agent(
  [
    HOUSE,
    '',
    CONTEXT,
    '',
    'Three independent designs follow. Choose one and write the implementation brief, grafting the',
    'best ideas from the others.',
    '',
    'Judge on one question above all: after this change, can an auditor asking "which person',
    'approved this?" get an answer that would survive challenge? A design that merely relabels a',
    'shared credential fails that test regardless of how much machinery it adds.',
    '',
    JSON.stringify(designs, null, 2),
    '',
    'Return a precise implementation brief including the migration for already-sealed records and',
    'whether an ADR is warranted. Do not edit anything.',
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
    chosen,
    '',
    'Apply it. Requirements:',
    '- Machine enforcement points must keep working unchanged. The PEP and SDK tests must pass.',
    '- Audit records must distinguish a human subject from a machine key on their face.',
    '- Add tests: a human action seals with the human subject; a machine action seals with the key',
    '  and is visibly unattributed; an actor field cannot be set by the caller.',
    '- Any Alembic migration must apply and reverse cleanly against an empty database.',
    '- Run "make check" and leave it green.',
    '- Write the ADR if the brief calls for one.',
    '',
    'Do not commit. Leave the working tree dirty for review.',
  ].join('\n'),
  { label: 'implement', phase: 'Implement', effort: 'high' }
)

phase('Attack')
const LENSES = [
  {
    key: 'forge-actor',
    probe:
      'Try to get a chosen actor value into a sealed audit record. Can a caller set it via a header, ' +
      'a body field, a principal id, a key name containing separator characters, or a unicode ' +
      'homoglyph of another user? Attempt it against the running code.',
  },
  {
    key: 'session-replay',
    probe:
      'Attack the console session. Token lifetime, refresh, logout, storage location, XSS reach, ' +
      'and whether a captured session can be replayed against the API directly. If OIDC was added, ' +
      'check signature validation, issuer and audience checks, and clock skew handling.',
  },
  {
    key: 'privilege-path',
    probe:
      'Attack the boundary between machine keys and human identity. Can a machine key perform an ' +
      'action that is supposed to require a person -- approving its own approval request, for ' +
      'instance? Can a low-scope key escalate by presenting itself as a user?',
  },
  {
    key: 'chain-integrity',
    probe:
      'Attack the audit chain itself under the new actor model. Does the actor participate in the ' +
      'content digest? Can two different actors produce the same sealed content? Does the migration ' +
      'of already-sealed records break "cpctl audit verify"? Run it.',
  },
]

const attacks = (
  await parallel(
    LENSES.map((l) => () =>
      agent(
        [
          HOUSE,
          '',
          CONTEXT,
          '',
          'A change has been applied. Summary:',
          applied || '(unavailable -- inspect with git diff)',
          '',
          'You are an attacker. Your goal is to make attribution wrong or forgeable. Report',
          'bypassed=true only for an attack you actually demonstrated, not one you suspect.',
          '',
          'Your lens: ' + l.key,
          l.probe,
        ].join('\n'),
        { label: 'attack:' + l.key, phase: 'Attack', schema: ATTACK_SCHEMA, effort: 'high' }
      )
    )
  )
).filter(Boolean)

const broken = attacks.filter((a) => a.bypassed)
log(broken.length ? broken.length + ' attack(s) succeeded' : 'no attack succeeded')

return { survey, designs, brief: chosen, applied, attacks, bypasses: broken, clean: broken.length === 0 }
