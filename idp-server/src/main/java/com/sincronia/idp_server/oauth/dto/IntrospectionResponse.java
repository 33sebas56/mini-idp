package com.sincronia.idp_server.oauth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record IntrospectionResponse(
        boolean active,

        @JsonProperty("token_type")
        String tokenType,

        @JsonProperty("client_id")
        String clientId,

        String sub,
        String iss,
        List<String> aud,
        Long exp,
        Long iat,
        String jti,
        String scope,
        String email
) {
    public static IntrospectionResponse inactive() {
        return new IntrospectionResponse(
                false,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }
}