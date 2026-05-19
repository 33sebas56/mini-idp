package com.sincronia.idp_server.audit;

import com.sincronia.idp_server.user.AppUser;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public void record(AppUser user, String eventType, HttpServletRequest request, String details) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        AuditLog auditLog = new AuditLog(
                user,
                eventType,
                ipAddress,
                userAgent,
                details
        );

        auditLogRepository.save(auditLog);
    }
}