# ROBOCARDANI License Manager — MVP v0.1

Painel web real com cadastro de clientes, licenças, renovação, bloqueio, histórico e API de validação. **Não está hospedado e não integra nem bloqueia o CYCLEFX PRO.**

## Pré-requisitos
Docker Engine e Docker Compose, servidor Linux, domínio e proxy reverso HTTPS (por exemplo, Caddy ou Nginx com certificado TLS).

## Iniciar em servidor
1. Copie `.env.example` para `.env`.
2. Gere valores secretos independentes e longos: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`. Execute uma vez para cada senha/segredo. **Não use os valores de exemplo.**
3. Execute `docker compose up -d --build`.
4. Configure o proxy HTTPS para encaminhar o domínio a `127.0.0.1:8000`. **Não exponha a porta 8000 diretamente na internet.**
5. Acesse `https://seu-dominio/`, entre com `ADMIN_USER` e `ADMIN_PASSWORD`.
6. Faça backups periódicos do volume PostgreSQL. Guarde o `.env` fora do repositório e restrinja acesso ao servidor.

## Testar localmente (sem Docker)
Crie ambiente virtual, instale `pip install -r requirements.txt`, copie e configure `.env` e execute `uvicorn app:app --reload`. O padrão local usa SQLite (`local.db`) somente para desenvolvimento. Em produção use PostgreSQL.

## API
`POST /api/admin/login` recebe `{ "username": "admin", "password": "..." }` e retorna token Bearer (4h).
Rotas administrativas exigem `Authorization: Bearer <token>`:
- `GET/POST /api/admin/clients`
- `GET/POST /api/admin/licenses`
- `POST /api/admin/licenses/{id}/block`
- `POST /api/admin/licenses/{id}/unblock`
- `POST /api/admin/licenses/{id}/renew` com `{ "days": 30 }`
- `GET /api/admin/audit`

A chave só é mostrada na emissão e é armazenada como HMAC-SHA256 no banco. A validação pública é:
```
POST /api/v1/validate
Content-Type: application/json
{"license_key":"RC-...", "mt5_login":"12345678", "mt5_server":"Nome-Servidor"}
```
Resposta: `{"valid": true|false, "server_time": "..."}`. A API **não** impede o EX5 do CYCLEFX PRO de executar.

## Segurança e limitações do MVP
- Use HTTPS obrigatório em produção, inclusive para validação pelo MT5. Nunca registre chaves em logs.
- Tokens de administrador ficam no `sessionStorage` da aba. Proteja a aplicação de scripts de terceiros e XSS; para ambiente comercial de maior escala migre para sessão em cookie HttpOnly com CSRF.
- Antes de disponibilizar a clientes: adicionar rate limiting, monitoramento, política de backup/restauração, migrações de banco (Alembic), testes automatizados e proteção contra tentativas repetidas de login/validação.
- O servidor de validação recebe a chave enviada pelo cliente. Uma chave no lado cliente pode ser copiada; o vínculo de conta/servidor reduz uso indevido, mas não é proteção inviolável.
- A validade é verificada no servidor. Licenças sem vencimento são permitidas pelo painel.
- O endpoint valida somente licenças emitidas pelo painel. **Nenhum indicador MT5 foi modificado nesta versão.**
- Não distribua o CYCLEFX PRO sem direito de redistribuição. O código do ROBOCARDANI apenas altera textos de objetos gráficos `CFX_DASH_` e não controla a lógica do CYCLEFX PRO.

## Próxima etapa
Adicionar `WebRequest` HTTPS ao código-fonte `ROBOCARDANI_2.mq5`, com verificação no `OnInit` e timer, estados de falha de rede e validade, e testes no MetaEditor/MT5. A função de personalização poderá ser desativada quando a licença falhar. Isso **não desativa o CYCLEFX PRO**.
