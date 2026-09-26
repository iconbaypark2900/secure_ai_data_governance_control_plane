export const meta = {
  name: 'classification-performance',
  description: 'Benchmark the scanner, then race four isolated optimisation spikes and pick winners',
  whenToUse:
    'Finding F-04. 50 req/s on one worker, 107 on four, p95 368ms at 8KB. Classification is ~0.6ms/KB CPU-bound and Python re only partially releases the GIL, so one worker is one core. That is a hard adoption ceiling for an inline data-path component.',
  phases: [
    { title: 'Baseline', detail: 'build and commit a repeatable benchmark, record current numbers' },
    { title: 'Spike', detail: 'four independent optimisations, each in its own worktree' },
    { title: 'Judge', detail: 'compare measured results and recommend what to land' },
  ],
}

const REPO = (args && args.repo) || '/home/iconbaypark2900/secure_ai_data_governance_control_plane'

const HOUSE = [
  'You are working in ' + REPO + ' -- a policy decision point for AI systems.',
  '',
  'House rules:',
  '- "make check" is the gate: ruff, mypy on control_plane/, pytest. 682 tests pass in ~14s.',
  '- ruff line-length 100, py312. mypy disallow_untyped_defs on control_plane/.',
  '- ADR 0006: sensitive values never reach durable storage.',
  '- Commits carry NO Co-Authored-By, Claude-Session, or any AI/assistant trailer.',
  '',
  'The project measures rather than assumes, and says so. The README records that API key hashing',
  'cost 82ms per request behind a source comment asserting it was "small next to a policy',
  'evaluation" -- written from plausibility and left standing until something measured it. Do not',
  'repeat that. Every claim you make in this workflow must come with a number you produced.',
].join('\n')

const RESULT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['approach', 'landed', 'msPerKbBefore', 'msPerKbAfter', 'speedup', 'testsPass', 'notes', 'risks'],
  properties: {
    approach: { type: 'string' },
    landed: { type: 'boolean', description: 'false if the approach turned out not to work' },
    msPerKbBefore: { type: 'number' },
    msPerKbAfter: { type: 'number' },
    speedup: { type: 'number' },
    testsPass: { type: 'boolean' },
    notes: { type: 'string' },
    risks: { type: 'array', items: { type: 'string' } },
  },
}

phase('Baseline')
const baseline = await agent(
  [
    HOUSE,
    '',
    'Task: build a repeatable classification benchmark and record the current numbers.',
    '',
    'Read control_plane/classification/scanner.py and detectors.py first. Then write',
    'tools/bench_classify.py that measures scan time per KB across a realistic corpus: a clean',
    'prompt, a prompt with one finding, a prompt dense with findings, an 8KB retrieval chunk (the',
    'shape a RAG pipeline actually sends), and a payload at the CP_MAX_SCAN_CHARS 64KiB limit.',
    '',
    'It must be deterministic, report median and p95, run in well under a minute, and take a',
    '--json flag so later agents can compare runs mechanically.',
    '',
    'Also profile where the time actually goes inside a scan -- per detector, and pattern matching',
    'versus structural validation versus context adjustment. The answer determines which of the',
    'downstream spikes is worth anything, so do not skip it.',
    '',
    'IMPORTANT: commit the benchmark to git when it works. Later agents run in fresh worktrees',
    'branched from HEAD and will not see uncommitted files. Commit message in the existing style,',
    'and with NO AI or assistant trailer of any kind.',
    '',
    'Return the recorded baseline numbers and the profile breakdown.',
  ].join('\n'),
  { label: 'baseline+profile', phase: 'Baseline', effort: 'high' }
)

phase('Spike')
const SPIKES = [
  {
    key: 'set-matching',
    brief:
      'Replace sequential Python re matching with a set-based matcher that tests all patterns in ' +
      'one pass -- google-re2, hyperscan bindings, or a compiled alternation with a dispatch table. ' +
      'Multi-pattern scanning typically gains 10-50x. Watch for semantic differences: RE2 does not ' +
      'support backreferences or lookaround, so check whether any existing detector relies on them ' +
      'and report honestly if the substitution is not clean. Adding a dependency is acceptable here ' +
      'if you justify it.',
  },
  {
    key: 'digest-cache',
    brief:
      'Cache classification results keyed by payload digest. A RAG pipeline re-sends identical ' +
      'chunks constantly, and pdp.py already computes a keyed content digest. Bound the cache, make ' +
      'it thread-safe, and be careful about a correctness trap: the cache must key on everything ' +
      'that affects the result, not just the payload -- if truncation limits or the enabled detector ' +
      'set can vary, they belong in the key. Measure hit rate on a realistic repeated-chunk workload ' +
      'as well as raw speed.',
  },
  {
    key: 'prefilter',
    brief:
      'Add a cheap prefilter that skips expensive detectors when a payload cannot possibly contain ' +
      'their target -- a fast scan for digit runs, "@", "-----BEGIN", and similar, gating the ' +
      'detectors that need them. Most real payloads contain no sensitive data at all, so the clean ' +
      'path is the one worth optimising. Prove the prefilter cannot produce a false negative: that ' +
      'is the whole risk, and a missed finding here is a governance failure, not a performance bug.',
  },
  {
    key: 'concurrency',
    brief:
      'Attack the GIL problem rather than the per-scan cost. Investigate a process pool for ' +
      'classification, the existing thread offload (the README records it measured only 1.25x and ' +
      'is kept for tail latency, not throughput), free-threaded Python 3.13, and whether the scan ' +
      'can release the GIL properly. Report what actually raises throughput per core, and be ' +
      'willing to conclude that nothing here does -- a negative result measured honestly is a ' +
      'valid outcome for this spike.',
  },
]

const results = (
  await parallel(
    SPIKES.map((s) => () =>
      agent(
        [
          HOUSE,
          '',
          'Baseline and profile from a prior agent:',
          baseline || '(unavailable -- run tools/bench_classify.py yourself first)',
          '',
          'You are running ONE optimisation spike in an isolated worktree. Other spikes are running',
          'in parallel on the same files -- ignore them, do not try to coordinate.',
          '',
          'Your spike: ' + s.key,
          s.brief,
          '',
          'Method:',
          '- Record the baseline with tools/bench_classify.py --json before you change anything.',
          '- Implement the change.',
          '- Re-run the same benchmark and record the after numbers.',
          '- Run the full test suite. A speedup that breaks classification is worth nothing, and',
          '  the 682 existing tests are the correctness contract.',
          '- If the approach does not work, say so and report landed=false with the numbers that',
          '  show it. A measured negative is a real result and more useful than a hedged positive.',
          '',
          'Report honest numbers. Do not extrapolate, do not round in your favour, and do not',
          'report a speedup you did not measure end to end.',
        ].join('\n'),
        {
          label: 'spike:' + s.key,
          phase: 'Spike',
          schema: RESULT_SCHEMA,
          isolation: 'worktree',
          effort: 'high',
        }
      )
    )
  )
).filter(Boolean)

const worked = results.filter((r) => r.landed && r.testsPass)
log(worked.length + '/' + results.length + ' spikes landed with tests passing')

phase('Judge')
const recommendation = await agent(
  [
    HOUSE,
    '',
    'Baseline:',
    baseline || '(unavailable)',
    '',
    'Four independent spikes ran in isolated worktrees. Their measured results:',
    JSON.stringify(results, null, 2),
    '',
    'Task: recommend what to land, in what order, and what to discard.',
    '',
    'Judge on:',
    '- Measured speedup, weighted by how much of the real request mix each approach helps. A 50x ',
    '  gain on a path that is 5% of the time is worth less than a 2x gain on the dominant one.',
    '- Correctness risk. The prefilter and the cache can both produce a missed finding, which is a',
    '  governance failure rather than a performance regression. Weight that heavily.',
    '- Whether approaches compose. Set matching plus a digest cache may multiply; two approaches',
    '  that both eliminate the same work do not.',
    '- Dependency and operational cost. This is a security component; a new native dependency has',
    '  a real supply-chain cost that a benchmark does not show.',
    '',
    'Then state plainly whether the combination clears the throughput ceiling the README documents,',
    'or only moves it. If a 500 chunk/second RAG pipeline still needs twenty cores, say so.',
    '',
    'Produce: a ranked recommendation, the exact merge order, what to discard and why, and a draft',
    'ADR in the existing docs/adr/ voice numbered from 0017. Do not merge anything yourself -- the',
    'spikes are in separate worktrees and the maintainer decides what lands.',
  ].join('\n'),
  { label: 'judge:recommendation', phase: 'Judge', effort: 'high' }
)

return { baseline, results, landed: worked, recommendation }
