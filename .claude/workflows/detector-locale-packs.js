export const meta = {
  name: 'detector-locale-packs',
  description: 'Add per-jurisdiction national identifier detectors, each with a real structural check',
  whenToUse:
    'Finding F-03. Of 28 detectors the only non-US identifier is IBAN, yet GDPR is claimed in the README headline example, in regulations_for(), and throughout the reference policies. Pass args.jurisdictions to override the default set.',
  phases: [
    { title: 'Research', detail: 'per jurisdiction: identifier formats and checksum algorithms' },
    { title: 'Design', detail: 'per jurisdiction: detector spec, context words, test vectors' },
    { title: 'Apply', detail: 'one agent integrates every spec into the taxonomy and scanner' },
    { title: 'Verify', detail: 'three adversaries: false positives, checksums, taxonomy coherence' },
  ],
}

const REPO = (args && args.repo) || '/home/iconbaypark2900/secure_ai_data_governance_control_plane'

const DEFAULT_JURISDICTIONS = [
  { code: 'uk', name: 'United Kingdom', hint: 'NINO, NHS number, UTR, driving licence number' },
  { code: 'de', name: 'Germany', hint: 'Steuer-Identifikationsnummer, Sozialversicherungsnummer, Personalausweis' },
  { code: 'fr', name: 'France', hint: 'INSEE / NIR social security number, SIREN, SIRET' },
  { code: 'es', name: 'Spain', hint: 'DNI, NIE, NUSS social security number' },
]

const JURISDICTIONS = (args && args.jurisdictions) || DEFAULT_JURISDICTIONS

const HOUSE = [
  'You are working in ' + REPO + ' -- a policy decision point for AI systems.',
  '',
  'House rules:',
  '- "make check" is the gate: ruff, mypy on control_plane/, pytest. 682 tests pass in ~14s.',
  '- ruff line-length 100, py312. mypy disallow_untyped_defs on control_plane/.',
  '- ADR 0006: sensitive values never reach durable storage. Test vectors must be synthetic.',
  '- Commits carry NO Co-Authored-By, Claude-Session, or any AI/assistant trailer.',
].join('\n')

const DETECTOR_RULES = [
  'The house rule for detectors, which is the whole point of this codebase:',
  '',
  'A detector pairs a pattern with a STRUCTURAL CHECK. A bare regex is not a detector here.',
  'Card numbers get Luhn. IBANs get mod-97. SSNs get the allocation rules. NPIs get the issuer',
  'prefix. If a national identifier has a checksum, it must be implemented; if it genuinely has',
  'none, say so explicitly and explain what else constrains it -- a fixed length plus a valid',
  'date component plus a region code is a structural check; nine arbitrary digits is not.',
  '',
  'Confidence is adjusted by context in both directions. In the existing US SSN detector:',
  '  "536-90-4432"        -> pii.ssn @ 0.85   written the way an SSN is written',
  '  "order 536904432"    -> nothing          nine digits is an order number',
  '  "SSN 536904432"      -> pii.ssn @ 0.90   the adjacent word is the evidence',
  '  {"ssn": "536904432"} -> pii.ssn @ 0.90   so is the field name',
  'Every locale needs its own context words in its own language -- "Steuer-ID", "numero fiscal",',
  '"numero de la seguridad social" -- not English ones.',
  '',
  'The taxonomy is honest about limits. pii.name ships with no detector because no regex finds a',
  "person's name. If a jurisdiction's identifier cannot be detected reliably, say so and do not",
  'ship something confidently wrong.',
].join('\n')

const RESEARCH_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['jurisdiction', 'identifiers'],
  properties: {
    jurisdiction: { type: 'string' },
    identifiers: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['name', 'label', 'format', 'structuralCheck', 'checkable', 'regulations', 'contextWords'],
        properties: {
          name: { type: 'string' },
          label: { type: 'string', description: 'proposed taxonomy label, e.g. pii.national_id.uk_nino' },
          format: { type: 'string' },
          structuralCheck: {
            type: 'string',
            description: 'the checksum or validity algorithm in enough detail to implement',
          },
          checkable: {
            type: 'boolean',
            description: 'false if there is genuinely no structural check available',
          },
          regulations: { type: 'array', items: { type: 'string' } },
          contextWords: {
            type: 'array',
            items: { type: 'string' },
            description: 'native-language words and field names that raise confidence',
          },
        },
      },
    },
  },
}

const SPEC_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['jurisdiction', 'detectors', 'taxonomyEntries', 'testVectors', 'rejected'],
  properties: {
    jurisdiction: { type: 'string' },
    detectors: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['label', 'pattern', 'validatorCode', 'baseConfidence'],
        properties: {
          label: { type: 'string' },
          pattern: { type: 'string' },
          validatorCode: { type: 'string', description: 'Python function body implementing the check' },
          baseConfidence: { type: 'number' },
        },
      },
    },
    taxonomyEntries: { type: 'array', items: { type: 'string' } },
    testVectors: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['input', 'expect', 'why'],
        properties: {
          input: { type: 'string', description: 'SYNTHETIC value only -- never a real identifier' },
          expect: { type: 'string', description: 'label expected, or "none"' },
          why: { type: 'string' },
        },
      },
    },
    rejected: {
      type: 'array',
      items: { type: 'string' },
      description: 'identifiers deliberately not shipped, and why',
    },
  },
}

const ADVERSARY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['problems', 'verdict'],
  properties: {
    verdict: { type: 'string', enum: ['ship', 'fix-first'] },
    problems: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['label', 'problem', 'example'],
        properties: {
          label: { type: 'string' },
          problem: { type: 'string' },
          example: { type: 'string' },
        },
      },
    },
  },
}

log('locale packs for: ' + JURISDICTIONS.map((j) => j.code).join(', '))

const specs = (
  await pipeline(
    JURISDICTIONS,
    (j) =>
      agent(
        [
          HOUSE,
          '',
          DETECTOR_RULES,
          '',
          'Research the national personal identifiers for ' + j.name + '.',
          'Likely candidates: ' + j.hint,
          '',
          'For each, establish the exact format, the checksum or structural validity algorithm in',
          'enough detail that someone can implement it without further research, the native-language',
          'context words and JSON field names that would appear next to it, and which regulations it',
          'implicates. Be rigorous about the checksum -- getting it wrong produces a detector that is',
          'confidently useless. If an identifier has no structural check, say so.',
          '',
          'Read control_plane/classification/detectors.py first to see the existing house style.',
          'Do not edit anything.',
        ].join('\n'),
        { label: 'research:' + j.code, phase: 'Research', schema: RESEARCH_SCHEMA }
      ),
    (research, j) =>
      agent(
        [
          HOUSE,
          '',
          DETECTOR_RULES,
          '',
          'Research for ' + j.name + ':',
          JSON.stringify(research, null, 2),
          '',
          'Turn this into an implementable detector spec matching the existing house style in',
          'control_plane/classification/detectors.py and control_plane/classification/taxonomy.py.',
          '',
          'Test vectors are the most important part. For each identifier supply: a valid synthetic',
          'value that must be detected; a value that is one digit off and must NOT be detected;',
          'a bare number in a non-identifier context that must NOT be detected; and a value with a',
          'native-language context word that must be detected at raised confidence. Every value you',
          'write must be synthetic -- construct it to satisfy the checksum, never copy a real one.',
          '',
          'Drop any identifier you cannot check structurally, and record it in "rejected" with the',
          'reason. Shipping nothing is better than shipping something confidently wrong.',
          '',
          'Do not edit anything -- return the spec only.',
        ].join('\n'),
        { label: 'design:' + j.code, phase: 'Design', schema: SPEC_SCHEMA }
      )
  )
).filter(Boolean)

log(specs.length + ' spec(s) ready; ' + specs.reduce((n, s) => n + s.detectors.length, 0) + ' detectors proposed')

phase('Apply')
const applied = await agent(
  [
    HOUSE,
    '',
    DETECTOR_RULES,
    '',
    'Integrate the following locale packs into the codebase. They were designed independently, so',
    'reconcile them: a single coherent labelling scheme, no duplicated helper code, and one',
    'consistent way of registering a locale.',
    '',
    JSON.stringify(specs, null, 2),
    '',
    'Requirements:',
    '- Locale packs are OPT-IN by configuration. A deployment that enables none must classify',
    '  exactly as it does today, and the existing 682 tests must still pass unchanged.',
    '- Extend control_plane/classification/taxonomy.py so the new labels map to the right',
    '  regulations, and check regulations_for() returns GDPR for the European ones.',
    '- Every test vector becomes a real test.',
    '- Measure the cost. Classification is the dominant CPU cost on the decision path at roughly',
    '  0.6 ms/KB, and adding detectors adds to it. Report the before and after per-KB scan time and',
    '  say plainly whether enabling a locale pack is affordable.',
    '- Update README.md and docs/policy-language.md where they state the detector count and the',
    '  taxonomy size. Keep the existing prose voice.',
    '- Write an ADR in docs/adr/ numbered from 0017 covering why packs are opt-in and why',
    '  identifiers without a structural check were rejected.',
    '- Run "make check" and leave it green.',
    '',
    'Do not commit. Leave the working tree dirty for review.',
  ].join('\n'),
  { label: 'apply:locale-packs', phase: 'Apply', effort: 'high' }
)

phase('Verify')
const ADVERSARIES = [
  {
    key: 'false-positives',
    probe:
      'You are trying to make the new detectors fire on things that are not identifiers. Feed them ' +
      'order numbers, invoice references, phone numbers, timestamps, git hashes, product SKUs, ' +
      'and the other locales’ identifiers. A detector that fires on a German invoice number is ' +
      'worse than no detector, because a policy will deny on it. Run the scanner directly.',
  },
  {
    key: 'checksum-truth',
    probe:
      'You are checking the structural checks are actually correct, independently of what the ' +
      'implementing agent believed. Re-derive each algorithm from first principles, then test the ' +
      'implementation against values you construct yourself. A checksum implemented wrong will ' +
      'pass the author’s own tests because the author generated the vectors from the same wrong ' +
      'understanding. That is the specific failure you are looking for.',
  },
  {
    key: 'taxonomy-coherence',
    probe:
      'You are checking the taxonomy still makes sense as a whole. Are the new labels hierarchically ' +
      'correct, so a policy naming "pii" still covers them? Do the regulation mappings hold? Does ' +
      'the reference policy set in seed/policies.yaml behave sensibly with a locale pack enabled, ' +
      'or does a European identifier now slip past rules written for US ones? Run the seed policy ' +
      'integration test with a pack enabled.',
  },
]

const findings = (
  await parallel(
    ADVERSARIES.map((a) => () =>
      agent(
        [
          HOUSE,
          '',
          DETECTOR_RULES,
          '',
          'Locale packs have been added. Summary:',
          applied || '(unavailable -- inspect with git diff)',
          '',
          'You are an adversary. Find what is wrong. Report verdict "ship" only if you genuinely',
          'could not break it.',
          '',
          'Your lens: ' + a.key,
          a.probe,
        ].join('\n'),
        { label: 'adversary:' + a.key, phase: 'Verify', schema: ADVERSARY_SCHEMA, effort: 'high' }
      )
    )
  )
).filter(Boolean)

const blocking = findings.filter((f) => f.verdict === 'fix-first')
log(blocking.length ? blocking.length + ' adversary/adversaries say fix first' : 'all adversaries say ship')

return {
  jurisdictions: JURISDICTIONS.map((j) => j.code),
  specs,
  applied,
  findings,
  blocking,
  clean: blocking.length === 0,
}
