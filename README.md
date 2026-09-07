# helpdesk-sandbox — multi-CWE support-desk corpus

A minimal Spring Boot support-ticket API carrying findings for all five enabled
CWEs at once. Not a real product; source is parsed, never deployed.

Unlike the `payroll-sandbox-*` series — which isolated a single axis each — this
one is deliberately mixed: **18 catalog-matching sink call sites across 5 CWEs**,
some resolvable from the graph and some not, plus a safe twin for every
vulnerable shape.

## Ground truth

### CWE-862 — Missing Authorization
Authenticated, but no role check.

| Handler | Route | Sink | Guard | Expected |
|---|---|---|---|---|
| `listTickets` | `GET /tickets` | `findAll()` | none | **TP** (AUTHZ_READ) |
| `ticketReport` | `GET /tickets/report` | `findAll()` | `@PreAuthorize("hasRole('AGENT')")` | safe |
| `ticketCount` | `GET /tickets/count` | `count()` | none | **TP** (AUTHZ_READ) |
| `deleteTicket` | `DELETE /tickets/{id}` | `deleteById()` | none | **TP** (AUTHZ_WRITE) |
| `purgeTicket` | `DELETE /tickets/{id}/purge` | `deleteById()` | `@Secured("ROLE_SUPERVISOR")` | safe |

### CWE-306 — Missing Authentication for Critical Function
`/public/**` is `permitAll()` in `SecurityConfig`, so these need no session.

| Handler | Route | Sink | Expected |
|---|---|---|---|
| `importTickets` | `POST /public/tickets/import` | `saveAll()` | **TP** (CRITICAL_MUTATION) |
| `submitTicket` | `POST /public/tickets/submit` | `save()` | **TP** (CRITICAL_MUTATION) |
| `scanAttachments` | `POST /public/tickets/scan` | `Runtime#exec` | **TP** (CRITICAL_EXEC) |
| `scanAttachmentsGuarded` | `POST /tickets/scan` | `Runtime#exec` | safe (authenticated + role) |

### CWE-639 — Authorization Bypass Through User-Controlled Key
The caller names the record in every case; only the `ForOwner` path checks it.

| Method | Sink | Ownership check | Expected |
|---|---|---|---|
| `openTicket` | `entityManager.find` | none | **TP** (IDOR_LOOKUP) |
| `openTicketForOwner` | `entityManager.find` | `callerId` vs `requesterId` | safe |
| `fetchTicket` | `ticketRepository.findById` | none | **TP** (IDOR_LOOKUP) |
| `fetchTicketSubject` | `jdbcTemplate.queryForObject` | none | **TP** (IDOR_LOOKUP) |
| `discardTicket` | `ticketRepository.deleteById` | none | **TP** (IDOR_MUTATION) |

### CWE-312 / CWE-319 — Cleartext storage and transmission
Requester email and phone are the sensitive payload throughout.

| Method | Sink | Type | Expected |
|---|---|---|---|
| `recordAccess` | `trail.info` | LOG_WRITE | **TP** (312) |
| `recordFailure` | `trail.error` | LOG_WRITE | **TP** (312) |
| `recordBridgeRetry` | `trail.warn` | LOG_WRITE | **TP** (312/319) |
| `exportTickets` | `Files.writeString` | FILE_WRITE | **TP** (312) |
| `notifyBridge` | `bridgeClient.send` → `http://` | NETWORK_WRITE | **TP** (319) |

## Why this one also exercises the LLM path

`sink_type_reasoning` settles a site for free when the graph can attribute the
receiver's class. It cannot when the sink's **simple class name** maps to more
than one qualified class in the catalog, and those sites escalate to the LLM.

This repo mixes both on purpose:

| Receiver | Simple class | Catalog owners | Path |
|---|---|---|---|
| `trail` | `Logger` | slf4j / log4j / java.util.logging | **LLM** |
| `entityManager` | `EntityManager` | jakarta / javax | **LLM** |
| `bridgeClient` | `HttpClient` | java.net.http / apache ×2 | **LLM** |
| `ticketRepository` | `TicketRepository` → `JpaRepository` | single | graph |
| `jdbcTemplate` | `JdbcTemplate` | single | graph |

So a scan should show roughly **6 sites reaching the LLM** (2× `EntityManager#find`,
`Logger#info`/`#warn`/`#error`, `HttpClient#send`) with the remainder confirmed
as `graph_proven`. That makes it a positive control for both halves of the step
in a single run — if `llm=0` here, the escalation path is broken, not idle.

## Layout

```
pom.xml
src/main/java/com/secsandbox/helpdesk/
    HelpdeskApplication.java     @EnableMethodSecurity(securedEnabled = true)
    SecurityConfig.java          /public/** is permitAll -> the CWE-306 premise
    Ticket.java                  @Entity, holds the PII
    TicketRepository.java        extends JpaRepository -> inherits the sinks
    TicketController.java        CWE-862 and CWE-306 sites, plus safe twins
    TicketLookupService.java     CWE-639 sites, three different receivers
    TicketAuditService.java      CWE-312 / CWE-319 sites
    AttachmentScanService.java   CWE-306 CRITICAL_EXEC
src/main/resources/application.properties
```

## Note on counts

The 18 figure counts call sites whose method name matches a catalog symbol —
the same name-first basis `sink_detection` uses. Some are then rejected in type
reasoning (`csv.append` matches an `append` symbol but the receiver is a
`StringBuilder`), so findings will be fewer than sites. That gap is expected and
is itself worth watching.
