# Ordered upstream failover (badigit fork)

Based on upstream 3.5.14. Both switches default to false; legacy weighted selection,
same-upstream retry behavior, and Middle-End egress identity remain unchanged by default.

```toml
[general]
upstream_failover = true
upstream_failover_probe = true
upstream_connect_retry_attempts = 3
upstream_connect_retry_backoff_ms = 0
upstream_connect_budget_ms = 9000
tg_connect = 3
upstream_unhealthy_fail_threshold = 1
```

When failover is enabled, eligible healthy upstreams are tried in configuration order,
then eligible unhealthy upstreams in configuration order. Each route is attempted once,
up to `upstream_connect_retry_attempts`. The first configured route is the primary.
Scope filtering is preserved; a scoped request never escapes its configured scope.
Hard errors skip that candidate without preventing attempts through distinct reserves.
The total budget covers DNS, proxy TCP, SOCKS negotiation, readiness probes and backoff.
The per-candidate deadline covers the whole operation, not each sub-stage separately.

Mihomo can acknowledge SOCKS CONNECT before its outbound connection succeeds.
For Direct-mode DC connections, the optional probe sends an anonymous MTProto
`req_pq_multi` request on a disposable tunnel and requires `resPQ` with the same nonce.
The probe has a 4096-byte response cap and shares the candidate/request deadlines.
After a successful probe, a fresh tunnel is opened for the actual user session.
The probe's cryptographic/transport state is never reused by the client.
This adds one tunnel and one round trip per attempted candidate. There is still a race
between a successful probe and the subsequent tunnel; it does not migrate established
sessions, replay user requests, or guarantee the second tunnel will remain healthy.
Middle-End connections and non-DC connections do not use this Direct-mode probe.

Health failures are attributed to the attempted route even if a reserve succeeds.
Connect success/failure metrics count the final request outcome; attempt metrics count
candidate attempts, not the extra physical sockets used by readiness probes.
Existing periodic checks can recover an upstream after it was marked unhealthy.
Changing these general switches requires a process restart to rebuild the manager.

Focused regression tests live in `src/transport/upstream/failover/tests.rs`.
Run `cargo test --locked --release transport::upstream::` with an external timeout.
The `Build tested failover binary` workflow builds a Linux binary after those tests.
