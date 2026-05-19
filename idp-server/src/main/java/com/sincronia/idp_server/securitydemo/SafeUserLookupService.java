package com.sincronia.idp_server.securitydemo;

import com.sincronia.idp_server.user.AppUserRepository;
import org.springframework.stereotype.Service;

@Service
public class SafeUserLookupService {

    private final AppUserRepository appUserRepository;

    public SafeUserLookupService(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    public SqlInjectionDemoResponse safeLookupByEmail(String email) {
        boolean found = appUserRepository.findByEmail(email.trim().toLowerCase()).isPresent();

        return new SqlInjectionDemoResponse(
                email,
                found,
                found ? 1 : 0,
                "Consulta protegida mediante Spring Data JPA y parámetros enlazados. No se concatena SQL."
        );
    }
}