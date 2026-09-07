package com.secsandbox.helpdesk;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * CWE-312 / CWE-319 surface: requester contact details reach a log file, a
 * plaintext export on disk, and an http:// webhook.
 *
 * Logger and HttpClient both have ambiguous simple class names in the catalog
 * (slf4j / log4j / j.u.l, and java.net.http / apache), so these sites cannot be
 * attributed from the graph and go to the LLM.
 */
@Service
public class TicketAuditService {

    private static final Logger trail = LoggerFactory.getLogger(TicketAuditService.class);

    private static final URI TICKET_BRIDGE = URI.create("http://ticket-bridge.internal/v1/events");

    private static final Path EXPORT_FILE = Path.of("/var/tmp/helpdesk-export.csv");

    private final HttpClient bridgeClient = HttpClient.newHttpClient();

    // VULNERABLE (CWE-312): requester email and phone land in the log.
    public void recordAccess(Ticket ticket, String actor) {
        trail.info("ticket {} opened by {} — requester {} / {}",
                ticket.getId(), actor, ticket.getRequesterEmail(), ticket.getRequesterPhone());
    }

    // VULNERABLE (CWE-312): the same contact details, on the failure path.
    public void recordFailure(Ticket ticket, Exception cause) {
        trail.error("ticket {} failed for requester {} ({})",
                ticket.getId(), ticket.getRequesterEmail(), ticket.getRequesterPhone(), cause);
    }

    // VULNERABLE (CWE-312, FILE_WRITE): PII written to a world-readable path.
    public void exportTickets(List<Ticket> tickets) throws Exception {
        StringBuilder csv = new StringBuilder("id,email,phone,subject\n");
        for (Ticket t : tickets) {
            csv.append(t.getId()).append(',')
               .append(t.getRequesterEmail()).append(',')
               .append(t.getRequesterPhone()).append(',')
               .append(t.getSubject()).append('\n');
        }
        Files.writeString(EXPORT_FILE, csv.toString(), StandardCharsets.UTF_8);
    }

    // VULNERABLE (CWE-319): ticket body plus contact details over plaintext http.
    public int notifyBridge(Ticket ticket) throws Exception {
        String payload = "{\"id\":" + ticket.getId()
                + ",\"email\":\"" + ticket.getRequesterEmail()
                + "\",\"body\":\"" + ticket.getBody() + "\"}";
        HttpRequest event = HttpRequest.newBuilder(TICKET_BRIDGE)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> reply = bridgeClient.send(event, HttpResponse.BodyHandlers.ofString());
        return reply.statusCode();
    }

    // VULNERABLE (CWE-319): the bridge URL is logged with its query string.
    public void recordBridgeRetry(Ticket ticket, String endpoint) {
        trail.warn("retrying bridge {} for requester {}", endpoint, ticket.getRequesterEmail());
    }
}
