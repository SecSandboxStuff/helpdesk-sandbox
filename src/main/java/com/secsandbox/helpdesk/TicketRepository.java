package com.secsandbox.helpdesk;

import org.springframework.data.jpa.repository.JpaRepository;

// Spring Data repo — inherits findAll(), findById(), count(), saveAll(),
// deleteById() from CrudRepository. Receiver type is declared, so the graph
// attributes these without the LLM.
public interface TicketRepository extends JpaRepository<Ticket, Long> {
}
