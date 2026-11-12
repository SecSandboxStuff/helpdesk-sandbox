package com.secsandbox.helpdesk;

import org.springframework.stereotype.Service;

/**
 * CWE-306 CRITICAL_EXEC surface: the antivirus sweep shells out, and the route
 * that reaches it sits under /public/**, so no authentication is required to
 * trigger it.
 */
@Service
public class AttachmentScanService {

    public int sweepAttachments(String attachmentDir) throws Exception {
        Process scan = Runtime.getRuntime().exec("/usr/local/bin/clamscan " + attachmentDir);
        return scan.waitFor();
    }
}

