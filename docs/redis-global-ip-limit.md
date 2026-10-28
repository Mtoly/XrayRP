# Redis global source-IP admission

`GlobalDeviceLimitConfig` can enforce one source-IP quota per panel UID across
all XrayRP nodes and processes that share a panel namespace. It covers the Xray
node data path and the AnyTLS, TUIC, and Hysteria2 runtime paths. The feature is
disabled by default; with `Enable: false`, XrayRP keeps its existing local-only
admission behavior.

This document describes the operational contract. It does not replace panel
configuration, and it does not by itself verify a deployment.

## What is counted

- The identity is the panel **UID**, not the credential string. UUID, password,
  and other authentication aliases for one UID share the same quota, including
  across protocols and nodes.
- One slot is one **normalized source address**. The same address counts once
  even when several connections, nodes, or protocols use it.
- IPv4 is counted as-is. IPv4-mapped IPv6 addresses are counted as IPv4. IPv6 is
  masked to an operator-selected prefix, so a client's rotating addresses inside
  one prefix occupy one slot.
- The quota is the effective per-UID device limit. A limit of `0` means "no
  per-UID limit from this registration"; see [Policy updates](#policy-updates).

Connections from an already admitted address do not consume a second slot. A
new address is admitted only while the UID holds fewer than the effective limit
of distinct addresses.

## Configuration

```yaml
ControllerConfig:
  GlobalDeviceLimitConfig:
    Enable: true
    RedisNetwork: tcp
    RedisAddr: 127.0.0.1:6379
    RedisUsername:
    RedisPassword: YOUR PASSWORD
    RedisDB: 0
    Timeout: 5
    Expiry: 60
    Mode: cache
    FailMode: open
    Namespace:
    IPv6Prefix: 64
    StrictClientIPSource: peer
```

| Field | Default | Meaning |
| --- | --- | --- |
| `Enable` | `false` | Turns shared admission on. When false, every other field is ignored and admission stays local. |
| `RedisNetwork` | `tcp` | `tcp` or `unix`. |
| `RedisAddr` | | `host:port`, or a Unix socket path when `RedisNetwork` is `unix`. |
| `RedisUsername` | empty | Optional Redis ACL user. |
| `RedisPassword` | empty | Redis password. Keep it secret. |
| `RedisDB` | `0` | Redis logical database. All participants that share a quota must use the same database. |
| `Timeout` | `5` | Budget for a new admission, including queueing, policy publication and reservation, in seconds; also bounds Redis network I/O. `0` means 5. Cancellation during an in-flight socket read can take until this timeout. |
| `Expiry` | `60` | Lease and policy-registration lifetime in seconds. Minimum 3; `0` means 60. |
| `Mode` | `cache` | `cache` or `strict`. See [Modes](#modes). |
| `FailMode` | `open` | `open` or `closed`. See [Redis failures](#redis-failures). |
| `Namespace` | empty | Optional shared key-space name. Hashed before use. When empty, the namespace is derived from panel type and `ApiHost`. |
| `IPv6Prefix` | `/64` when omitted | IPv6 mask length from `0` to `128`. An explicit `0` counts the full address. |
| `StrictClientIPSource` | `peer` | Acknowledgment only; it does not select or verify the source address. In `strict` mode with `TrustedXForwardedFor` set, `forwarded` is required. Accepts `peer` or `forwarded`. |

`Expiry` and `Timeout` are accepted as `0` for the defaults above. A negative
value, an `Expiry` below 3, an `IPv6Prefix` outside `0`–`128`, or an unknown
`Mode`, `FailMode`, or `StrictClientIPSource` fails configuration validation at
startup.

The same block is valid under `MachineConfig.ControllerConfig`. It applies to
every server discovered in machine mode.

## Namespace

The namespace selects the shared key space. Nodes can enforce one quota only
when they resolve the same namespace.

- With `Namespace` set, XrayRP hashes the value. The literal string is never
  used as a Redis key, so it cannot leak panel identity or credentials.
- With `Namespace` empty, XrayRP derives the namespace from the canonical panel
  type and the canonical panel API URL: scheme, lowercased host (including
  port), and API path. URL credentials and query strings are not part of the
  basis. `V2board` and `NewV2board` resolve to the same canonical type.
- If neither `Namespace` nor both panel type and API host are available, startup
  fails rather than falling back to a guess.

Changing the namespace starts a new key space. Leases under the old namespace
are not migrated and expire by TTL, so the shared quota starts empty.

## Modes

### `cache` (default)

Existing cache-style behavior plus the shared reservation. A local reservation
confirmed within the last `Expiry` may be reused without another Redis round
trip. New distinct addresses still go through the atomic quota check, but an
already admitted address is not evicted when another node lowers the limit.
This is the compatibility mode, not a strict distributed guarantee.

### `strict`

Every new connection is verified against Redis, and the quota decision, the
reservation, and the policy minimum are evaluated in one atomic operation. There
is no confirmed-reservation reuse, so the shared quota holds without a cache
window as long as Redis is reachable and `FailMode` does not admit unverified
connections. Use this mode when the quota must be enforced consistently across
nodes.

`strict` is only as strong as the configuration and the participants:

- `FailMode: open` reintroduces a local fallback exactly when Redis is
  unavailable. Pair `strict` with `FailMode: closed` when new connections must
  be rejected rather than admitted on unverified local state.
- A node that is not participating, an older XrayRP version, a node with a
  different namespace, or a node with a different `IPv6Prefix`, `Mode`, or
  Redis database defeats the shared guarantee for its own connections.

## Source address selection

The admitted address is the address XrayRP sees for the connection:

- Xray nodes use the inbound source address. An authenticated connection whose
  source is not an IP address is closed before admission. This guard applies to
  every authenticated Xray node connection, not only when Redis admission is
  enabled.
- AnyTLS, TUIC, and Hysteria2 use the connection's remote address.

When `ControllerConfig.TrustedXForwardedFor` is configured, Xray can derive the
source from a forwarded header. In `strict` mode, XrayRP refuses to start
unless `StrictClientIPSource: forwarded` acknowledges that. The acknowledgement
does not verify proxy CIDRs, rewrite headers, or change the address XrayRP uses.
It is a configuration signal, not a security boundary.

Header and PROXY protocol trust stay operator responsibilities. Restrict origin
access to trusted proxies, sanitize `X-Forwarded-For` at the edge, and restrict
which origins may send PROXY protocol to `EnableProxyProtocol` inbounds.

## Redis failures

`FailMode` controls what happens when Redis cannot confirm admission.

### `open` (default)

A failed Redis reservation does not by itself reject the connection. XrayRP
falls back to a process-local quota view and keeps serving, so the connection is
then subject to that local quota and can still be rejected when it is full. The
distributed guarantee is suspended until Redis is usable again, and readiness
reports degraded. Local enforcement cannot see addresses held by other nodes, so
a prolonged outage weakens the shared quota.

### `closed`

A new connection is rejected whenever its reservation cannot be confirmed with
Redis. In `strict` mode every connection needs that confirmation, so the first
failed request denies. In `cache` mode a reservation confirmed within `Expiry`
may still be reused until the failure is detected and it is marked lost; after
that, and whenever the circuit breaker is open, new connections are denied.
Existing connections are not interrupted.

`closed` trades availability for consistency. During a prolonged outage,
existing leases stop renewing and expire in Redis, so the shared quota stops
being enforced for those connections while new connections keep being rejected.
Readiness stays degraded until every live holder is confirmed again.

### Shared behavior

- Repeated failures open a short circuit breaker so XrayRP does not hammer an
  unavailable Redis.
- In `FailMode: open`, a Redis failure creates a committed local-only lease whose
  slot is intentionally counted locally, so the process still has a bounded
  quota. A request that is rejected for another reason does not leak a slot:
  tentative leases are aborted, and a rejected local admission releases its
  reservation before returning.
- Leases lost during an outage are never restored unconditionally. They are
  reacquired only if the current quota still allows it, and readiness remains
  degraded until all live holders are confirmed.

## Renewal and expiry

- Each accepted connection holds a lease. Lease renewal runs every
  `Expiry / 3` seconds while at least one connection for that UID and address
  remains open, including idle connections. Renewal is what keeps a slot
  occupied.
- A lease belongs to the logical connection. For Xray, that means both
  directions of a link must finish before the lease is released.
- Closing the last connection for a UID and address stops renewal but does not
  delete the Redis entry. The entry expires by TTL. There is no cross-node
  deletion and no distributed reference count.
- After a crash, leases from the lost process expire within `Expiry` seconds.
  No manual cleanup is required.
- An expiring lease never closes user connections. It only frees the slot for
  future admissions.

## Policy updates

Each runtime registers the device limit already resolved by its panel adapter;
Redis does not introduce another local override. For Xboard/NewV2board, a positive
user `device_limit` takes precedence over `ApiConfig.DeviceLimit`; if the panel
value is zero or absent, the local `ApiConfig.DeviceLimit` is used. Other panel
adapters retain their existing mapping rules.

Each runtime publishes those limits for the users it knows. The effective limit
for a UID is the smallest positive limit among live registrations. Registrations
renew even on a node where that user currently has no connection.

- A registration of `0` does not override another registration's positive
  limit. It also does not add a limit when all registrations are `0`.
- Raising a limit takes effect for new addresses only after the previous lower
  registration updates or expires. Until then, the lower value still applies.
- Lowering a limit does not evict addresses that are already admitted. The
  lower value governs new addresses.
- Registrations expire after `Expiry` seconds without renewal. This bounds the
  influence of a crashed or removed node.

User limit changes are published on user synchronization. Existing connections
are not reevaluated against the new policy.

## Panel device snapshots

When Redis admission is active, panel-provided device data is not used for
admission. Specifically:

- Xboard/NewV2board `sync.devices` snapshots are stored but do not admit or
  reject connections.
- The panel alive list (applied through `SyncAliveList`) does not crop or
  rewrite the local online-IP view of an inbound that uses Redis admission.
- For Xray nodes, online-user reporting and the limiter state snapshot return
  the live reservations held by XrayRP rather than the panel snapshot. AnyTLS,
  TUIC, and Hysteria2 keep reporting their own tracked connection IPs.
- Renewal is driven by open connections, not by panel state.

With Redis admission disabled, all of the above keeps its existing behavior.

## Protocol coverage

The shared manager is wired into all four paths:

| Path | Implementation | Test status |
| --- | --- | --- |
| Xray node data path (all Xray node types) | Limiter acquires a lease per logical link. | An opt-in real VLESS/TCP connection test exercises two managed node tags on one Xray core, including deduplication, quota rejection, idle renewal and expiry. Other Xray protocol/transport combinations are not individually wire-tested by this test. |
| AnyTLS | Service acquires a lease per accepted connection. | An opt-in Redis test with real AnyTLS connections exists. |
| TUIC | Service acquires a lease per accepted connection. | An opt-in Redis test with real TUIC connections exists; it requires a `with_quic` build. |
| Hysteria2 | Authentication acquires a lease per session. | An opt-in Redis test with real Hysteria2 connections exists. |

The opt-in tests require a disposable Redis and are not part of the default
`go test ./...` run:

```bash
XRAYRP_RUN_REDIS_INTEGRATION=1 \
XRAYRP_REDIS_ADDR=127.0.0.1:16379 \
go test -count=1 ./common/limiter ./service/controller ./service/anytls ./service/hysteria2 -run Redis -v
```

TUIC additionally needs a `-tags with_quic` build. The default test and build
paths do not include the QUIC runtime.

The limiter acceptance tests in `common/limiter` cover quota, deduplication,
cross-process enforcement, namespace isolation, lease renewal, crash expiry,
policy minimums, and Redis outage recovery. The service tests drive the same
manager through real AnyTLS, TUIC, and Hysteria2 connections.

This document does not record test results. Treat integration coverage as
requiring a real environment run, and treat production behavior as unverified
until you run it in your own deployment. Do not infer that a path is validated
because a test file exists.

## Migration and key layout

- New state lives under a dedicated key prefix (`xrayrp:gli:<namespace>:...`)
  with its own layout. It does not read or overwrite the older per-user cache
  entries, so enabling the feature does not require clearing Redis and does not
  inherit stale cache data.
- Leases and policy registrations carry a TTL bounded by `Expiry`, so keys left
  behind by a crashed or removed node disappear without manual deletion.
- Do not delete keys by hand. If you need a clean slate, use a new `Namespace`;
  the old key space expires on its own.
- Upgrades must be coordinated. An older XrayRP version keeps using its previous
  cache behavior and keys and does not participate in the shared quota, so the
  strict shared guarantee does not hold until every participating node runs the
  new version. During the transition, old and new nodes do not share state.
- Rolling back to an older XrayRP leaves the new keys behind to expire. Older
  versions do not read them.
- Nodes that must count independently need different namespaces or Redis
  databases. Nodes that share a quota need the same namespace, `Mode`,
  `IPv6Prefix`, and Redis database. `FailMode` is a per-node availability choice
  and does not change which keys are used.

## Deployment checklist

1. Upgrade every node that participates in the shared quota. Older versions do
   not read the new keys and do not participate.
2. Give all participating nodes the same Redis address and DB, the same
   `Namespace` (or the same panel type and `ApiHost`), the same `Mode`, and the
   same `IPv6Prefix`. Mismatched values create separate quotas or unstable
   counting.
3. Choose `FailMode` deliberately. `open` favors availability and falls back to
   a process-local quota; `closed` rejects new connections that cannot be
   confirmed, including during a Redis outage.
4. If `TrustedXForwardedFor` is configured, strict mode requires
   `StrictClientIPSource: forwarded`. Restrict the proxy origin either way and
   sanitize the forwarded header. PROXY protocol alone does not trigger this
   validation; apply the same origin restriction to `EnableProxyProtocol`
   inbounds.
5. Do not delete Redis keys by hand. Keys use a dedicated prefix, expire by TTL,
   and cannot collide with the older per-user cache entries.
6. In machine mode, put the block under `MachineConfig.ControllerConfig`. The
   namespace is derived from `MachineConfig.PanelType` and `MachineConfig.ApiHost`
   unless `Namespace` is set.

## Observability

While the shared guarantee is weakened, `/readyz` includes the reason
`global_device_limit_unavailable` and reports `degraded`. When every other check
passes that is HTTP 200 `degraded`, not `not_ready`: the runtime is still
serving, but Redis admission could not confirm its reservations. If another
condition also makes the runtime unusable, `/readyz` returns HTTP 503 and lists
every failing reason.

A `closed`-mode outage therefore shows up as rejected new connections plus this
readiness reason, not as a `not_ready` response on its own.

No separate metric is exported for this condition. Metrics still carry the
per-runtime lifecycle and failure labels; use the readiness reasons together
with connection logs when diagnosing an outage.

## Limits

- This is not a panel-side verification and does not replace authentication,
  panel device limits, or traffic limits.
- It cannot guarantee a quota when only some nodes participate, when a node
  runs an older version, or when `cache` mode is used.
- It never disconnects or evicts established connections. Lowering a limit or
  losing a lease affects future admissions only.
- IPv6 prefix grouping may merge customers that share one operator prefix. A
  shorter prefix length (for example `/56` instead of `/64`) groups more
  addresses; an explicit `0` counts each full address separately.
- Redis server time drives lease expiry, so all participants share one clock.
- The shared quota is per namespace. Two panels that must not share devices
  need different namespaces or Redis databases.
- Renewal for one process runs as a single serial round: it republishes the
  policy view, then renews each live reservation in turn, under one deadline of
  `Expiry / 2`. Renewal rounds start every `Expiry / 3`.

  Size the deployment so the round comfortably fits `Expiry / 2` on the
  expected holder count and Redis round-trip time. Approximate cost is
  `holders × Redis RTT` plus policy publishing. When a round cannot reach every
  holder in time, the unreached reservations are marked lost and retried on the
  next tick; readiness reports degraded. In `strict` mode, new connections still
  require their own successful Redis admission; the backlog alone is not a
  blanket rejection switch. Existing connections keep running.

  This is a sizing guideline, not a guaranteed holder count. Raise `Expiry` or
  reduce the number of tracked holders per process when a round does not fit.
