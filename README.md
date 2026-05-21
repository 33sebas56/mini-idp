# Mini IdP

Mini IdP es un servidor de identidad desarrollado con Spring Boot. Implementa registro de usuarios, verificación por correo, autenticación con contraseña y TOTP, emisión de JWT firmados, exposición de JWKS, OAuth Authorization Code Flow, refresh token con rotación, introspección, revocación y una aplicación cliente que valida tokens emitidos por el IdP.

## URLs desplegadas

| Servicio | URL |
|---|---|
| IdP | https://miniidp-idp.duckdns.org |
| Client App | https://miniidp-app.duckdns.org |
| JWKS | https://miniidp-idp.duckdns.org/.well-known/jwks.json |

## Arquitectura

```text
Usuario
  |
  | HTTPS
  v
Nginx Reverse Proxy
  |
  |-- miniidp-idp.duckdns.org  -> idp-server:9000
  |
  |-- miniidp-app.duckdns.org  -> client-app:8080
  |
Docker Compose
  |
  |-- idp-server
  |-- client-app
  |-- PostgreSQL
```

## Componentes

| Componente | Descripción |
|---|---|
| `idp-server` | Servidor de identidad. Registra usuarios, verifica correo, autentica, emite tokens y expone JWKS. |
| `client-app` | Aplicación cliente que usa OAuth Authorization Code Flow y valida JWT con JWKS. |
| `PostgreSQL` | Base de datos para usuarios, clientes OAuth, tokens, TOTP, claves y auditoría. |
| `Nginx` | Reverse proxy público con HTTPS. |
| `DuckDNS` | DNS dinámico usado para exponer los subdominios públicos. |
| `Certbot / Let's Encrypt` | Certificados TLS para HTTPS. |

## Tecnologías usadas

| Tecnología | Uso |
|---|---|
| Java 21 | Lenguaje principal |
| Spring Boot | Backend |
| Spring Security | Seguridad, headers, filtros y validación JWT |
| Spring Data JPA | Persistencia |
| PostgreSQL | Base de datos |
| Flyway | Migraciones SQL |
| Docker Compose | Orquestación de servicios |
| Nginx | Reverse proxy |
| Certbot | TLS |
| DuckDNS | DNS |
| Gmail SMTP | Envío de correo de verificación |

## Funcionalidades principales

| Funcionalidad | Estado |
|---|---|
| Registro de usuario | Implementado |
| Verificación de correo por SMTP | Implementado |
| Login con contraseña | Implementado |
| Configuración TOTP con QR | Implementado |
| Login con segundo factor TOTP | Implementado |
| OAuth Authorization Code Flow | Implementado |
| Emisión de JWT | Implementado |
| Firma JWT con RS256 | Implementado |
| JWKS público | Implementado |
| Validación JWT desde client-app | Implementado |
| Refresh token | Implementado |
| Rotación de refresh token | Implementado |
| Revocación de token | Implementado |
| Introspección de token | Implementado |
| Auditoría de eventos | Implementado |
| Demo anti SQL Injection | Implementado |
| HTTPS con dominio público | Implementado |

## Flujo principal

```text
1. El usuario entra a client-app.
2. client-app redirige al IdP.
3. El IdP solicita correo y contraseña.
4. El IdP valida TOTP.
5. El IdP genera authorization code.
6. client-app intercambia el code por tokens.
7. El IdP entrega access token y refresh token.
8. client-app valida el JWT usando el JWKS del IdP.
9. El usuario accede al dashboard protegido.
```

## Seguridad implementada

| Control | Implementación |
|---|---|
| Contraseñas | Hash con BCrypt |
| Segundo factor | TOTP basado en tiempo |
| Tokens | JWT firmado con RS256 |
| Claves públicas | Expuestas mediante JWKS |
| Clave privada | Almacenada cifrada en base de datos |
| Refresh token | Rotación y revocación |
| OAuth client | `client_id`, `client_secret`, `redirect_uri` y scopes |
| Headers de seguridad | CSP, X-Frame-Options, X-Content-Type-Options |
| SQL Injection | Uso de Spring Data JPA y parámetros enlazados |
| Auditoría | Registro de eventos críticos |
| HTTPS | Nginx + Certbot + Let's Encrypt |

## Endpoints principales

### IdP

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/` | Página principal del IdP |
| GET | `/register` | Formulario de registro |
| POST | `/register` | Registro desde formulario web |
| POST | `/auth/register` | Registro vía API |
| GET | `/auth/verify-email` | Verificación de correo |
| POST | `/auth/login` | Login por API |
| POST | `/auth/totp/setup` | Generación de TOTP |
| POST | `/auth/totp/confirm` | Confirmación de TOTP |
| POST | `/auth/totp/verify-login` | Validación TOTP en login |
| GET | `/totp-setup` | Configuración visual de TOTP |
| GET | `/.well-known/jwks.json` | Claves públicas JWKS |
| GET | `/oauth/authorize` | Inicio OAuth Authorization Code |
| POST | `/oauth/token` | Intercambio de code o refresh token |
| POST | `/oauth/introspect` | Introspección de token |
| POST | `/oauth/revoke` | Revocación de token |
| GET | `/security/sql-injection-demo` | Demo de protección SQL Injection |

### Client App

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/` | Página principal |
| GET | `/login` | Inicio de flujo OAuth |
| GET | `/callback` | Callback OAuth |
| GET | `/dashboard` | Dashboard autenticado |
| GET | `/protected-profile` | Vista web del endpoint protegido |
| GET | `/api/profile` | API protegida por Bearer Token |
| GET | `/refresh-token` | Renovación de access token |
| GET | `/logout` | Cierre de sesión local |

## Despliegue

El despliegue se realizó en una máquina virtual de Azure con Ubuntu Server.

### Infraestructura usada

```text
Azure VM
Ubuntu Server 24.04
Docker Compose
Nginx
Certbot
DuckDNS
PostgreSQL en contenedor
idp-server en contenedor
client-app en contenedor
```

### Puertos públicos

| Puerto | Uso |
|---|---|
| 22 | SSH |
| 80 | HTTP / validación Certbot |
| 443 | HTTPS |

Los puertos internos `8080`, `9000` y `5432` no se exponen públicamente.

## Variables de entorno

El archivo real de despliegue es:

```text
.env.deploy
```

Este archivo no debe subirse al repositorio porque contiene secretos.

Variables principales:

```env
POSTGRES_DB=
POSTGRES_USER=
POSTGRES_PASSWORD=

APP_ISSUER=
CLIENT_BASE_URL=
APP_ENCRYPTION_SECRET=
APP_OAUTH_CLIENT_SECRET=
APP_OAUTH_REDIRECT_URI=

SMTP_HOST=
SMTP_PORT=
SMTP_USERNAME=
SMTP_PASSWORD=
APP_MAIL_FROM=

IDP_ISSUER=
IDP_JWKS_URI=
IDP_AUTHORIZATION_URI=
IDP_TOKEN_URI=

OAUTH_CLIENT_ID=
OAUTH_CLIENT_SECRET=
OAUTH_REDIRECT_URI=
```

Importante:

```text
APP_OAUTH_CLIENT_SECRET y OAUTH_CLIENT_SECRET deben tener el mismo valor.
```

## Ejecución con Docker Compose

```bash
sudo docker compose --env-file .env.deploy -f docker-compose.deploy.yml up -d --build
```

Ver contenedores:

```bash
sudo docker ps
```

Probar servicios internos:

```bash
curl http://127.0.0.1:9000/health
curl http://127.0.0.1:8080/health
```

Probar servicios públicos:

```bash
curl https://miniidp-idp.duckdns.org/health
curl https://miniidp-app.duckdns.org/health
```

## Guía rápida de demo

```text
1. Abrir https://miniidp-idp.duckdns.org
2. Crear cuenta desde /register.
3. Verificar correo desde el enlace recibido.
4. Configurar TOTP desde /totp-setup.
5. Abrir https://miniidp-app.duckdns.org.
6. Iniciar sesión.
7. Completar contraseña y TOTP.
8. Ver dashboard autenticado.
9. Ver endpoint protegido desde /protected-profile.
10. Renovar access token.
11. Consultar JWKS.
12. Probar SQL Injection demo.
13. Revisar auditoría en PostgreSQL.
```

## Pruebas recomendadas

### Health check

```bash
curl https://miniidp-idp.duckdns.org/health
curl https://miniidp-app.duckdns.org/health
```

### JWKS

```bash
curl https://miniidp-idp.duckdns.org/.well-known/jwks.json
```

### Endpoint protegido sin token

```bash
curl -i https://miniidp-app.duckdns.org/api/profile
```

Resultado esperado:

```text
HTTP/1.1 401
WWW-Authenticate: Bearer
```

### SQL Injection demo

```bash
curl "https://miniidp-idp.duckdns.org/security/sql-injection-demo?email=%27%20OR%20%271%27%3D%271"
```

Resultado esperado:

```text
found=false
returnedRows=0
```

### Refresh tokens en base de datos

```bash
sudo docker exec -it mini-idp-postgres psql -U mini_idp_user -d mini_idp
```

```sql
select client_id, revoked_at, replaced_by_token_hash, expires_at
from refresh_tokens
order by created_at desc
limit 10;
```

### Auditoría

```sql
select event_type, created_at
from audit_logs
order by created_at desc
limit 30;
```

Eventos esperados:

```text
USER_REGISTERED
EMAIL_VERIFIED
TOTP_SETUP_STARTED
TOTP_ENABLED
OAUTH_PASSWORD_ACCEPTED_TOTP_REQUIRED
OAUTH_AUTHORIZATION_CODE_ISSUED
OAUTH_TOKEN_ISSUED
OAUTH_REFRESH_TOKEN_ROTATED
```

## Consideraciones

El despliegue usa una sola VM de Azure con separación lógica mediante contenedores, dominios y Nginx. La arquitectura permite registrar múltiples aplicaciones cliente mediante la tabla `oauth_clients`, aunque la demo incluye una aplicación cliente funcional.

La separación física en múltiples instancias y un flujo formal de recuperación por pérdida de TOTP quedan como mejoras futuras.
