export const meta = {
  name: 'ship-distribution',
  description: 'Publish the packages, image and chart so someone can run this without cloning a repo',
  whenToUse:
    'Finding F-06. Neither SDK is on PyPI or npm, there is no image on any registry, no Helm chart, and no key backup or DR procedure. The fastest path to trying it is cloning a repo and reading a Makefile. This is the cheapest large win available.',
  phases: [
    { title: 'Prepare', detail: 'one agent per artifact, in parallel' },
    { title: 'Assemble', detail: 'reconcile into one release process' },
    { title: 'Prove', detail: 'consume each artifact the way a stranger would' },
  ],
}

const REPO = (args && args.repo) || '/home/iconbaypark2900/secure_ai_data_governance_control_plane'

const HOUSE = [
  'You are working in ' + REPO + ' -- a policy decision point for AI systems, Apache 2.0.',
  '',
  'House rules:',
  '- "make check" is the gate: ruff, mypy on control_plane/, pytest. 682 tests pass in ~14s.',
  '- CI lives in .github/workflows/ci.yml and already builds the Docker image, runs the suite',
  '  against live Postgres and Qdrant, applies and reverses migrations, and fails on a stale SDK',
  '  contract fixture. Extend it; do not replace it.',
  '- The project is version 0.1.0 and has never been released. Nothing is depending on stability',
  '  yet, so get the naming right now rather than later.',
  '- Commits carry NO Co-Authored-By, Claude-Session, or any AI/assistant trailer.',
  '',
  'Two secrets are required in production and the service refuses to start without them rather',
  'than minting ephemeral ones. CP_AUDIT_HMAC_KEY seals the chain and CP_TOKENIZATION_KEY is the',
  'only way to reverse a token. Losing either is unrecoverable. Any deployment artifact you produce',
  'must make that impossible to get wrong by accident.',
].join('\n')

const ARTIFACT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['artifact', 'summary', 'files', 'blockers', 'namingDecision'],
  properties: {
    artifact: { type: 'string' },
    summary: { type: 'string' },
    files: { type: 'array', items: { type: 'string' } },
    blockers: {
      type: 'array',
      items: { type: 'string' },
      description: 'anything requiring a human decision or credential the workflow cannot supply',
    },
    namingDecision: { type: 'string', description: 'the published name and why' },
  },
}

const PROOF_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['pass', 'whatWasTried', 'detail'],
  properties: {
    pass: { type: 'boolean' },
    whatWasTried: { type: 'string' },
    detail: { type: 'string' },
  },
}

phase('Prepare')
const ARTIFACTS = [
  {
    key: 'python-sdk',
    brief:
      'Prepare sdk/python for PyPI. The distribution name matters: the importable package is ' +
      'control_plane_sdk and the repo name is unwieldy. Recommend a name that is available, ' +
      'searchable and says what it is. Get the metadata right -- classifiers, license, README, ' +
      'python_requires, typing marker -- and add a build and publish job to CI gated on a tag, ' +
      'using trusted publishing rather than a long-lived token.',
  },
  {
    key: 'typescript-sdk',
    brief:
      'Prepare sdk/typescript for npm. It is currently named @control-plane/sdk, which is almost ' +
      'certainly an unavailable or squatted scope -- check and recommend a real one. Verify the ' +
      'build output works for both ESM and CJS consumers and that types resolve. Add a publish job ' +
      'gated on a tag with provenance enabled. The generated contract fixture check in CI must keep ' +
      'passing.',
  },
  {
    key: 'container-image',
    brief:
      'Publish the image to GHCR. Read the existing Dockerfile first. Add multi-arch (amd64 and ' +
      'arm64 -- the maintainer runs a DGX Spark, so arm64 is not hypothetical), a non-root user, a ' +
      'pinned base, an SBOM, build provenance, and sensible tags including a digest. The image must ' +
      'refuse to start without the required secrets rather than generating ephemeral ones, which is ' +
      'existing behaviour you must not accidentally defeat with a convenience default in an ' +
      'ENV line.',
  },
  {
    key: 'helm-chart',
    brief:
      'Write a Helm chart. The API is stateless and scales horizontally; Postgres is the one ' +
      'stateful component. Cover: replica count and WEB_CONCURRENCY (one worker is one core, which ' +
      'makes CPU requests load-bearing rather than decorative), the required secrets sourced from a ' +
      'Secret and never a values default, the migration job ordering ahead of the app, health and ' +
      'readiness probes against /health and /ready, a NetworkPolicy keeping /metrics and the ' +
      'database off the open network, and optional deployment of the two PEPs. Lint it.',
  },
  {
    key: 'key-runbook',
    brief:
      'Write the operational runbook the README currently lacks: key generation, backup separate ' +
      'from the database, rotation, and disaster recovery. Rotation is the hard part and the ' +
      'interesting one -- the audit chain is sealed under CP_AUDIT_HMAC_KEY and tokens are only ' +
      'reversible under CP_TOKENIZATION_KEY, so naive rotation breaks verification of historical ' +
      'records and orphans every existing token. Work out what rotation actually means for each ' +
      'key, whether the code supports it today, and what would have to change. If the honest answer ' +
      'is that rotation is currently impossible, say so plainly -- that is a finding worth having.',
  },
]

const prepared = (
  await parallel(
    ARTIFACTS.map((a) => () =>
      agent(
        [
          HOUSE,
          '',
          'Prepare one distribution artifact. Read the relevant existing files before writing.',
          '',
          'Your artifact: ' + a.key,
          a.brief,
          '',
          'Write the files. Do not publish anything, do not push, and do not commit -- publishing is',
          'the maintainer decision and needs credentials you do not have. Record anything blocking',
          'in "blockers" rather than working around it.',
        ].join('\n'),
        { label: 'prepare:' + a.key, phase: 'Prepare', schema: ARTIFACT_SCHEMA }
      )
    )
  )
).filter(Boolean)

const blockers = prepared.flatMap((p) => p.blockers.map((b) => p.artifact + ': ' + b))
log(prepared.length + ' artifacts prepared, ' + blockers.length + ' blockers needing a human')

phase('Assemble')
const assembled = await agent(
  [
    HOUSE,
    '',
    'Five artifacts were prepared independently. Reconcile them into one coherent release process.',
    '',
    JSON.stringify(prepared, null, 2),
    '',
    'Requirements:',
    '- One version number across the Python package, the npm package, the image and the chart, with',
    '  one documented way to bump it. Four artifacts drifting apart is the failure mode here.',
    '- One release workflow in .github/workflows/, tag-triggered, that builds and publishes',
    '  everything in the right order and refuses to publish if the test suite or the SDK contract',
    '  check fails.',
    '- A RELEASING.md describing the process, including the manual steps the blockers identified.',
    '- Update README.md so the quick start leads with the published artifacts rather than "make',
    '  install". Keep the existing prose voice. The current quick start assumes a clone; a reader',
    '  who has not cloned anything should reach a running control plane in one command.',
    '- Reconcile the naming decisions into one answer, and note whether the repository itself should',
    '  be renamed -- the current name is 45 characters and unsearchable.',
    '',
    'Do not commit and do not publish. Leave the working tree dirty for review.',
  ].join('\n'),
  { label: 'assemble:release', phase: 'Assemble', effort: 'high' }
)

phase('Prove')
const PROOFS = [
  {
    key: 'cold-start',
    probe:
      'You are a stranger who has never seen this repository. Build the image locally, follow only ' +
      'the new README quick start, and get a control plane answering a real /v1/decide call. Use ' +
      'nothing that is not in the documented path. Report every place you had to guess, look at ' +
      'source, or already know something to proceed. Guessing counts as a failure.',
  },
  {
    key: 'chart-and-image',
    probe:
      'Lint and template the Helm chart against a real Kubernetes schema, and dry-run install it if ' +
      'a cluster is available. Verify the image runs as non-root, refuses to start without the ' +
      'required secrets, and passes its probes. Confirm the chart cannot be installed with a ' +
      'default or empty audit key -- that is the failure that produces a chain which verifies today ' +
      'and breaks after the next restart.',
  },
  {
    key: 'packages',
    probe:
      'Build both SDK packages and install them into clean environments from the built artifacts ' +
      'rather than from source. Import them, run the documented example against a local control ' +
      'plane, and confirm types resolve for a TypeScript consumer in both ESM and CJS. Then ' +
      'regenerate the SDK contract fixture and confirm the two clients still agree.',
  },
]

const proofs = (
  await parallel(
    PROOFS.map((p) => () =>
      agent(
        [
          HOUSE,
          '',
          'Release artifacts have been prepared. Summary:',
          assembled || '(unavailable -- inspect with git diff)',
          '',
          'Actually run the thing. Do not read the files and reason about whether they would work --',
          'execute the path and report what happened. pass=true only for something you observed.',
          '',
          'Your lens: ' + p.key,
          p.probe,
        ].join('\n'),
        { label: 'prove:' + p.key, phase: 'Prove', schema: PROOF_SCHEMA, effort: 'high' }
      )
    )
  )
).filter(Boolean)

const failed = proofs.filter((p) => !p.pass)
log(failed.length ? failed.length + ' proof(s) failed' : 'all proofs passed')

return { prepared, blockers, assembled, proofs, failures: failed, clean: failed.length === 0 }
