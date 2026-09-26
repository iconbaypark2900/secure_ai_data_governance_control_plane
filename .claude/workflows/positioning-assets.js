export const meta = {
  name: 'positioning-assets',
  description: 'Reposition around agent tool-call governance and produce the assets that carry it',
  whenToUse:
    'Roadmap phase 4. The MCP proxy is the sharpest and least-served thing here and it is presented as item five of nine. Zero stars, no writeup, no demo, and a 45-character name. This costs engineering nothing and is where the return is currently highest.',
  phases: [
    { title: 'Evidence', detail: 'establish what can be truthfully claimed, from the code' },
    { title: 'Draft', detail: 'five assets in parallel' },
    { title: 'Fact-check', detail: 'every claim traced back to code or a measurement' },
  ],
}

const REPO = (args && args.repo) || '/home/iconbaypark2900/secure_ai_data_governance_control_plane'

const HOUSE = [
  'You are working in ' + REPO + ' -- a policy decision point for AI systems, Apache 2.0.',
  '',
  'The voice of this project is its main asset and it is unusual. The README and the sixteen ADRs',
  'argue rather than assert, and they record being wrong: an API key hash that cost 82ms behind a',
  'comment asserting it was cheap; a tokenise strategy that silently degraded to hash; a filter',
  'that two test files had corrected in their own queries. That candour is why the documentation',
  'is persuasive.',
  '',
  'So: no marketing voice. No superlatives, no "revolutionary", no "enterprise-grade", no feature',
  'bullets that restate the same claim three ways. Write the way the README already writes. If a',
  'claim needs a caveat, the caveat goes in the same sentence.',
  '',
  'Every factual claim must be traceable to code or to a measurement in the repository. Do not',
  'invent benchmark numbers, adoption figures, or comparisons you have not verified. An unsupported',
  'claim in a project whose whole thesis is "a claim without evidence is worth nothing" is a',
  'self-inflicted wound.',
  '',
  'Commits carry NO Co-Authored-By, Claude-Session, or AI trailer.',
].join('\n')

const THESIS = [
  'The repositioning thesis, from the market assessment:',
  '',
  'The sharpest wedge is pep/mcp_proxy. Agent tool-call governance is the least-served problem in',
  'this space: MCP has become the de facto tool protocol, agents are reaching production faster',
  'than controls for them, and "an agent pasted a customer record into a web search" is a story',
  'every enterprise security team recognises immediately.',
  '',
  'The distinction the repo already draws -- governing what an agent DOES, not just what it SAYS --',
  'is a position nobody owns. It is also the most demonstrable component: verified against a live',
  'gateway fronting 118 real tools across seven MCP servers, with 118 tools filtered to 73 for one',
  'agent, a filesystem write refused before it ran, and a patient file returned with the SSN',
  'redacted and the email pseudonymised.',
  '',
  'Adjacent categories and why none of them is this: guardrails vendors filter prompt content but',
  'have no catalog, no ABAC over classifications and no cryptographic audit; Immuta and Privacera',
  'enforce at the store and are absent from the request path; OPA and Cedar evaluate policy but',
  'cannot classify; Presidio detects without authorising; AI gateways route and cache with',
  'governance as a thin bolt-on.',
].join('\n')

const ASSET_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['asset', 'path', 'summary', 'claims'],
  properties: {
    asset: { type: 'string' },
    path: { type: 'string', description: 'file written, or "none" for a recommendation' },
    summary: { type: 'string' },
    claims: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['claim', 'source'],
        properties: {
          claim: { type: 'string' },
          source: { type: 'string', description: 'file:line, command output, or measurement' },
        },
      },
    },
  },
}

const CHECK_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['unsupported', 'verdict'],
  properties: {
    verdict: { type: 'string', enum: ['publishable', 'fix-first'] },
    unsupported: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['asset', 'claim', 'problem'],
        properties: {
          asset: { type: 'string' },
          claim: { type: 'string' },
          problem: { type: 'string' },
        },
      },
    },
  },
}

phase('Evidence')
const evidence = await agent(
  [
    HOUSE,
    '',
    THESIS,
    '',
    'Task: establish the evidence base before anyone writes a word of copy.',
    '',
    'Read pep/mcp_proxy/ and control_plane/adapters/mcp_gateway.py closely. Then actually run the',
    'MCP proxy against a live or mock MCP server and record what happens: the real tools/list',
    'filtering numbers, a refused tool call and the JSON-RPC error it returns, and a tool result',
    'rewritten on the way back. Capture real terminal output.',
    '',
    'Also collect the load-bearing numbers from the repository -- test counts, detector counts,',
    'throughput and latency figures, the 332x sampling finding, the 82ms API key measurement -- and',
    'note for each whether it is currently reproducible or is a historical claim in the README that',
    'nobody can re-derive today. Anything in the second category must not be used as a headline',
    'claim without re-measuring.',
    '',
    'Do not write copy. Return the evidence base.',
  ].join('\n'),
  { label: 'evidence:mcp', phase: 'Evidence', effort: 'high' }
)

phase('Draft')
const ASSETS = [
  {
    key: 'readme-lead',
    brief:
      'Restructure README.md so the agent story leads. Today it opens with the general thesis and ' +
      'reaches the MCP proxy as item five of nine. The reader you want -- a platform or security ' +
      'engineer whose agents are already in production -- should see the thing that speaks to them ' +
      'within the first screen. Keep the existing prose voice and the existing content; this is a ' +
      'reordering and a reframing, not a rewrite. Do not delete the general thesis, demote it.',
  },
  {
    key: 'mcp-demo',
    brief:
      'Produce a reproducible demo of the MCP proxy: a script under scripts/ or tools/ that stands ' +
      'up a mock MCP server with a realistic tool set, runs the proxy in front of it, and shows ' +
      'tools filtered, a call refused before it ran, and a result redacted on the way back. It must ' +
      'run from a clean clone in one command. Write the recording script and a shot list for a ' +
      '90-second screen capture, with the exact terminal commands in order.',
  },
  {
    key: 'adr-writeups',
    brief:
      'Turn the two strongest ADRs into standalone posts under docs/writing/: ADR 0011 (the Argon2id ' +
      'measurement -- a password hash defending 192 bits of entropy, 82ms per request, a source ' +
      'comment written from plausibility) and ADR 0009 (tokenisation without a vault -- why the ' +
      'obvious implementation concentrates the exact data the component exists to reduce). Both ' +
      'stand on their own for a general engineering audience and both demonstrate judgement better ' +
      'than any feature list. Keep them technical; do not soften them into blog-voice.',
  },
  {
    key: 'positioning-page',
    brief:
      'Write docs/positioning.md: an honest statement of what this is, who it is for, and what it ' +
      'is not, including the landscape comparison in the thesis above. Be accurate about the ' +
      'competitors rather than dismissive -- claiming Immuta cannot do something it can would be ' +
      'caught immediately and would cost more credibility than the comparison gains. Include the ' +
      'existing "What this is not" content and the known limitations from SECURITY.md, because ' +
      'stating them is the thing that makes the rest believable.',
  },
  {
    key: 'naming',
    brief:
      'The repository name is 45 characters, unsearchable, and impossible to say aloud. Propose ' +
      'five alternatives with the reasoning for each, check availability on GitHub, PyPI and npm, ' +
      'and recommend one. Also recommend whether to rename at all -- a rename breaks every existing ' +
      'link and the repository has no adoption to protect, which cuts both ways. Write the ' +
      'recommendation to docs/naming.md; do not rename anything.',
  },
]

const drafts = (
  await parallel(
    ASSETS.map((a) => () =>
      agent(
        [
          HOUSE,
          '',
          THESIS,
          '',
          'Evidence base from a prior agent -- use these numbers and nothing you cannot source:',
          evidence || '(unavailable -- gather it yourself before writing)',
          '',
          'Your asset: ' + a.key,
          a.brief,
          '',
          'List every factual claim you make with its source. A claim you cannot source must be',
          'cut, not hedged. Do not commit.',
        ].join('\n'),
        { label: 'draft:' + a.key, phase: 'Draft', schema: ASSET_SCHEMA }
      )
    )
  )
).filter(Boolean)

log(drafts.length + ' assets drafted, ' + drafts.reduce((n, d) => n + d.claims.length, 0) + ' claims to check')

phase('Fact-check')
const CHECKERS = [
  {
    key: 'claim-tracing',
    probe:
      'Take every claim from every asset and independently verify it against the code or by running ' +
      'the command. Do not accept the drafting agent source citation -- open the file, run the test, ' +
      'check the number. Flag anything you cannot confirm, anything stated more strongly than the ' +
      'evidence supports, and any number quoted from the README that cannot be re-derived today.',
  },
  {
    key: 'competitor-accuracy',
    probe:
      'Check every claim made about another product -- Immuta, Privacera, Lakera, Presidio, OPA, ' +
      'Skyflow, the AI gateways. Is each one accurate and current? A comparison that overstates a ' +
      'competitor limitation is the fastest way to lose the credibility this project is trading on. ' +
      'Flag anything you would not be comfortable defending to an engineer who works on that ' +
      'product. Where a claim is stale or unverifiable, say what it should be softened to.',
  },
  {
    key: 'voice',
    probe:
      'Read the drafts against README.md and the ADRs. Does the voice match? Flag anything that ' +
      'reads as marketing: superlatives, a claim without its caveat, a feature list restating one ' +
      'point three ways, or a limitation moved to a footer. Also flag the opposite failure -- ' +
      'hedging so heavy the reader cannot tell what the thing does. The README manages to be both ' +
      'confident and candid; the drafts must too.',
  },
]

const checks = (
  await parallel(
    CHECKERS.map((c) => () =>
      agent(
        [
          HOUSE,
          '',
          'Drafted assets:',
          JSON.stringify(drafts, null, 2),
          '',
          'You are a fact-checker, not an editor. Report verdict "publishable" only if you found',
          'nothing that needs fixing first.',
          '',
          'Your lens: ' + c.key,
          c.probe,
        ].join('\n'),
        { label: 'check:' + c.key, phase: 'Fact-check', schema: CHECK_SCHEMA, effort: 'high' }
      )
    )
  )
).filter(Boolean)

const problems = checks.flatMap((c) => c.unsupported)
log(problems.length ? problems.length + ' unsupported or overstated claim(s)' : 'all claims check out')

return { evidence, drafts, checks, problems, clean: problems.length === 0 }
