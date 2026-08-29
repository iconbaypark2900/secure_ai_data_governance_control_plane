# 16. A second enforcement point, for tool calls

Status: accepted

## Context

The MCP adapter mapped tool calls onto decisions and nothing called it. 118 tools
on a real gateway were catalogued, classified, and correctly labelled, and an
agent could call any of them without the control plane hearing about it. A
mapping helper with no caller is a governance claim with nothing behind it.

The reverse proxy governs what an agent *says* to a model. This governs what an
agent *does*: the tools it calls, the arguments it sends, and the data those
tools hand back.

## Decision

A second reference enforcement point, `pep/mcp_proxy/`, sitting in front of an
MCP server. It governs three things and forwards everything else unchanged.

**The call, before it happens.** Arguments are the data leaving the agent. A
denial is a JSON-RPC error carrying the request's id and the decision id, not an
HTTP error: an HTTP 403 kills the session, while a JSON-RPC error is a normal
recoverable answer to one call, which is what a refusal should be.

**The result, after it does.** A file read returns whatever the file held, which
the agent never asked for by name. The result is classified and redacted in
place: text blocks are rewritten, image and resource blocks are passed through
untouched rather than being pretended about, and the block structure survives so
a client indexing into `content[]` still finds what it expects.

**The listing.** A tool the agent may not call need not be advertised. This is
not a substitute for governing the call -- an agent can name a tool it was never
shown, and the call is decided independently -- but not offering a capability is
cheaper than refusing it afterwards.

### The listing is advisory and deliberately unaudited

Filtering asks the control plane one question per tool with `persist=False`.
Recording those looked obviously right and was wrong. Against a gateway fronting
118 tools, a single `tools/list` wrote 360 decision records, none of which had an
outcome, twenty times the volume of the calls themselves. That buries the
`?outcome=unreported` filter -- which exists to make an enforcement point that
stopped reporting visible -- under advisory questions that never had an outcome
to report.

Nothing is carried out when a listing is filtered. No data moves. The enforcement
happens at the call. `persist=False` is for asking a question rather than taking
an action, and this is the case it is for.

## What running it against a real gateway found

**An obligation was being reported as discharged without being carried out.** The
reverse proxy declared it could satisfy `route` on both directions. On the way in
that is true and is how a backend gets chosen. On the way back there is nothing
to route: the response already exists, produced by whatever backend the request
went to. Since a claimed obligation is a discharged one, a `route` obligation
attached to a `return` action was reported satisfied while nothing routed
anything.

Two fixes, because there were two mistakes. The satisfiable set is now split by
direction, so the response path declares only `limit` and `watermark` -- what
`apply_response_obligations` can actually do. And the shipped routing policy no
longer matches `return`, because routing a result that already exists is
meaningless, which the policy's own comment had already argued about database
reads without noticing it applied here too.

This was found because the new enforcement point made the same claim and could
not back it up: it raised `ObligationUnsatisfied` where the older one had quietly
carried on. Two enforcement points disagreeing is how the first one's assumption
became visible.

**The shipped policy set had no rule for tool results.** Every call succeeded and
every result was withheld by deny-by-default. Correct, and useless. Added
`allow-tool-results-back-redacted`, kept separate from the read grant: reading an
asset is a question about something the catalog knows, while a tool result is
content that did not exist until the call ran.

## Consequences

A result can be withheld after the call has already run. That is worth doing --
it is the difference between the agent having the data and not -- but it cannot
undo a side effect. The error says so explicitly and tells the agent not to
retry, because a runtime that reads "denied" as "failed" may call a destructive
tool twice. A duty that must *prevent* an action has to be attached to the
invocation, not to its result.

Filtering a listing costs one evaluation per tool. Against 118 tools that is
~630ms cold and ~8ms warm, since the decisions are pure authorisation questions
with no payload and the SDK caches them.

The proxy is not transparent to latency and does not try to be. It is transparent
to the protocol, which is the property that matters: verified against a live
gateway by comparing the handshake, the session id, and the framing against the
same calls made directly.
