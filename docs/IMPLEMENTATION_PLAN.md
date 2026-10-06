# SurfaceWatch V1 implementation plan

Repository assessment on 2026-10-06: the user's repository was empty (no branches,
code, README, dependencies, or existing work to preserve). The repository identity
was retained after the account was renamed to Sushinull during development.

1. Build normalized TCP, DNS and TLS observations with a bounded safe scanner.
2. Implement and test a separate comparison engine before the web interface.
3. Store immutable snapshots and normalized evidence with PostgreSQL migrations.
4. Expose authenticated APIs and a PostgreSQL-backed queue; run one worker process.
5. Add repeat-observation confirmation, scheduler and a notification outbox.
6. Build a responsive React interface on the API, including explicit uncertainty.
7. Provide Docker deployment, an isolated demo lab, tests and documentation.
8. Review failures, scope changes, authentication, dependency advisories and migrations.

Decisions: React + Vite instead of Next.js because no server rendering is required;
PostgreSQL queue and scheduler polling instead of Redis/Celery/APScheduler because
one process can claim durable jobs and due timestamps without duplicate jobs after
restart. The scanner and diff engine remain independent of this execution choice.
