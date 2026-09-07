package com.secsandbox.helpdesk;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity
public class Ticket {

    @Id
    private Long id;
    private Long requesterId;
    private String requesterEmail;
    private String requesterPhone;
    private String subject;
    private String body;
    private String status;

    public Long getId() { return id; }
    public Long getRequesterId() { return requesterId; }
    public String getRequesterEmail() { return requesterEmail; }
    public String getRequesterPhone() { return requesterPhone; }
    public String getSubject() { return subject; }
    public String getBody() { return body; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}
