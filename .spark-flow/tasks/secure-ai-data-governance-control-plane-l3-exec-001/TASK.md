# Task: secure-ai-data-governance-control-plane-l3-exec-001

## Description

L3 execution model smoke: liaison doctor + reporter closeout

## Human-in-the-loop rule

Each agent writes its phase result to:

`.spark-flow/tasks/secure-ai-data-governance-control-plane-l3-exec-001/outbox/<phase>.md`

The human reviews it and runs:

`spark-flow approve <phase>`

or:

`spark-flow reject <phase> "reason"`
