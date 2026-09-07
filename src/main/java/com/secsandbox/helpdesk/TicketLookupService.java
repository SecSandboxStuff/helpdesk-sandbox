package com.secsandbox.helpdesk;

import java.util.Optional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * CWE-639 surface: every lookup here is keyed by an id the caller supplies,
 * and only {@link #openTicketForOwner} checks that the ticket belongs to them.
 *
 * Three different lookup receivers on purpose:
 *   - EntityManager  — simple class is ambiguous (jakarta / javax), so
 *                      sink_type_reasoning cannot settle it from the graph
 *   - TicketRepository — declared Spring Data type, graph-attributable
 *   - JdbcTemplate   — single-owner simple class, also graph-attributable
 */
@Service
public class TicketLookupService {

    @PersistenceContext
    private EntityManager entityManager;

    private final TicketRepository ticketRepository;
    private final JdbcTemplate jdbcTemplate;

    public TicketLookupService(TicketRepository ticketRepository, JdbcTemplate jdbcTemplate) {
        this.ticketRepository = ticketRepository;
        this.jdbcTemplate = jdbcTemplate;
    }

    // VULNERABLE (CWE-639): caller names the ticket, nothing checks ownership.
    public Ticket openTicket(Long ticketId) {
        return entityManager.find(Ticket.class, ticketId);
    }

    // SAFE: same lookup, but the result is rejected unless the caller owns it.
    public Ticket openTicketForOwner(Long ticketId, Long callerId) {
        Ticket found = entityManager.find(Ticket.class, ticketId);
        if (found == null || !callerId.equals(found.getRequesterId())) {
            throw new IllegalStateException("ticket " + ticketId + " is not yours");
        }
        return found;
    }

    // VULNERABLE (CWE-639): repository lookup on a caller-supplied id.
    public Optional<Ticket> fetchTicket(Long ticketId) {
        return ticketRepository.findById(ticketId);
    }

    // VULNERABLE (CWE-639): raw JDBC read keyed by the same untrusted id.
    public String fetchTicketSubject(Long ticketId) {
        return jdbcTemplate.queryForObject(
                "SELECT subject FROM ticket WHERE id = ?", String.class, ticketId);
    }

    // VULNERABLE (CWE-639, IDOR_MUTATION): caller-supplied id drives the delete.
    public void discardTicket(Long ticketId) {
        ticketRepository.deleteById(ticketId);
    }
}
