package com.secsandbox.helpdesk;

import java.util.List;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Ticket API. Authenticated but unguarded handlers are the CWE-862 sites; the
 * /public/** handlers are unauthenticated, which makes their critical
 * mutations CWE-306. Guarded twins exist for both so a detector that fires on
 * the shape rather than the guard is visible immediately.
 */
@RestController
public class TicketController {

    private final TicketRepository ticketRepository;
    private final TicketLookupService lookupService;
    private final TicketAuditService auditService;
    private final AttachmentScanService scanService;

    public TicketController(TicketRepository ticketRepository,
                            TicketLookupService lookupService,
                            TicketAuditService auditService,
                            AttachmentScanService scanService) {
        this.ticketRepository = ticketRepository;
        this.lookupService = lookupService;
        this.auditService = auditService;
        this.scanService = scanService;
    }

    // ── CWE-862: authenticated, but no role check ────────────────────────────

    // VULNERABLE: dumps every ticket in the system.
    @GetMapping("/tickets")
    public List<Ticket> listTickets() {
        return ticketRepository.findAll();
    }

    // SAFE: same read, role-guarded.
    @PreAuthorize("hasRole('AGENT')")
    @GetMapping("/tickets/report")
    public List<Ticket> ticketReport() {
        return ticketRepository.findAll();
    }

    // VULNERABLE: discloses total ticket volume.
    @GetMapping("/tickets/count")
    public long ticketCount() {
        return ticketRepository.count();
    }

    // VULNERABLE: any authenticated user can delete any ticket.
    @DeleteMapping("/tickets/{ticketId}")
    public void deleteTicket(@PathVariable Long ticketId) {
        lookupService.discardTicket(ticketId);
    }

    // SAFE: same delete, role-guarded.
    @Secured("ROLE_SUPERVISOR")
    @DeleteMapping("/tickets/{ticketId}/purge")
    public void purgeTicket(@PathVariable Long ticketId) {
        lookupService.discardTicket(ticketId);
    }

    // ── CWE-639: caller names the record ─────────────────────────────────────

    // VULNERABLE: no ownership check on the returned ticket.
    @GetMapping("/tickets/{ticketId}")
    public Ticket viewTicket(@PathVariable Long ticketId, @RequestParam String actor) {
        Ticket ticket = lookupService.openTicket(ticketId);
        auditService.recordAccess(ticket, actor);
        return ticket;
    }

    // SAFE: ownership is checked before the ticket is returned.
    @GetMapping("/tickets/{ticketId}/mine")
    public Ticket viewOwnTicket(@PathVariable Long ticketId, @RequestParam Long callerId) {
        return lookupService.openTicketForOwner(ticketId, callerId);
    }

    // VULNERABLE: repository lookup on an unchecked id.
    @GetMapping("/tickets/{ticketId}/status")
    public String ticketStatus(@PathVariable Long ticketId) {
        return lookupService.fetchTicket(ticketId).map(Ticket::getStatus).orElse("unknown");
    }

    // VULNERABLE: raw JDBC read on an unchecked id.
    @GetMapping("/tickets/{ticketId}/subject")
    public String ticketSubject(@PathVariable Long ticketId) {
        return lookupService.fetchTicketSubject(ticketId);
    }

    // ── CWE-312 / CWE-319: contact details leave the app ─────────────────────

    // VULNERABLE: writes requester PII to a plaintext export on disk.
    @Secured("ROLE_SUPERVISOR")
    @PostMapping("/tickets/export")
    public int exportTickets() throws Exception {
        List<Ticket> all = ticketRepository.findAll();
        auditService.exportTickets(all);
        return all.size();
    }

    // VULNERABLE: ships ticket body and contact details over plaintext http.
    @Secured("ROLE_SUPERVISOR")
    @PostMapping("/tickets/{ticketId}/notify")
    public int notifyBridge(@PathVariable Long ticketId) throws Exception {
        Ticket ticket = lookupService.openTicketForOwner(ticketId, 0L);
        return auditService.notifyBridge(ticket);
    }

    // ── CWE-306: no authentication at all on these routes ────────────────────

    // VULNERABLE: unauthenticated bulk write.
    @PostMapping("/public/tickets/import")
    public int importTickets(@RequestBody List<Ticket> incoming) {
        return ticketRepository.saveAll(incoming).size();
    }

    // VULNERABLE: unauthenticated single write.
    @PostMapping("/public/tickets/submit")
    public Ticket submitTicket(@RequestBody Ticket ticket) {
        return ticketRepository.save(ticket);
    }

    // VULNERABLE: unauthenticated command execution.
    @PostMapping("/public/tickets/scan")
    public int scanAttachments(@RequestParam String attachmentDir) throws Exception {
        return scanService.sweepAttachments(attachmentDir);
    }

    // SAFE: same sweep, behind authentication and a role check.
    @Secured("ROLE_SUPERVISOR")
    @PostMapping("/tickets/scan")
    public int scanAttachmentsGuarded(@RequestParam String attachmentDir) throws Exception {
        return scanService.sweepAttachments(attachmentDir);
    }
}
