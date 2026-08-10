# MasuGate calendar operation pack

This independently versioned pack exposes only `calendar.event.create` and
`calendar.event.cancel`. Creation is restricted to one configured calendar,
one non-recurring event with a bounded title and description, explicit RFC3339
timestamps and an IANA timezone. It has no attendee, notifications,
conferencing, attachment, move, or arbitrary-metadata fields.

The pack is a `reference-effect`: the PostgreSQL reference profile has a
compiled policy admission path, shared pending resolution with database leases. A
durable decision fence is written before protected dispatch, so expiry cannot
replace a decision after an effect begins and recovery resumes the same identity.
It has immutable resolution replays, worker recovery, and pinned LangGraph, MAF,
CrewAI, and OpenClaw create/cancel lifecycle evidence. It is not a production
vendor profile. The server-owned calendar provider adds the immutable event
reference; it is not model input.

This artifact contains no deployment binding, credential, host adapter, or
framework integration.
