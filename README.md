# auth-gateway

One login in front of the tools on the server (Grafana, ChirpStack, Prometheus, ...): the same
Telegram magic link as the other systems, with app `ops`. Only an approval in Telegram lets anyone in.

```
browser ─► Traefik ─► forwardAuth ─► auth-gateway /auth/verify ─► n8n session-check (app "ops")
              │           200 + X-WEBAUTH-USER: let through
              │           302: to jarllindquist.com/auth/login (approve in Telegram)
              └─► grafana.jarllindquist.com, chirpstack.jarllindquist.com, ...
```

## Lock a service

Put the service on `traefik-net` and add the middleware to its router:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.grafana.rule=Host(`grafana.jarllindquist.com`)"
  - "traefik.http.routers.grafana.entrypoints=websecure"
  - "traefik.http.routers.grafana.tls.certresolver=myresolver"
  - "traefik.http.routers.grafana.middlewares=ops-auth@docker"
```

The subdomain needs a DNS record (A to the server). A service that trusts `X-WEBAUTH-USER`
(Grafana's auth proxy) must only be reachable through Traefik: Traefik replaces the header with
the gateway's answer, but a request that goes around Traefik could set it itself.

## How it works

- `/auth/login`: the page. The button asks n8n (`request-magic-link`, app `ops`) to send an
  approval request to Telegram; the page then polls `/auth/login/status` until it is approved.
- On approval the n8n session id is set as cookie `ops_session` for `jarllindquist.com` and every
  subdomain (`HttpOnly`, `Secure`, `SameSite=Lax`). It holds nothing else: n8n decides whether it is
  valid, so there is no signing key to keep.
- `/auth/verify`: asked by Traefik before every request. n8n's answer is cached for a minute (a no
  for ten seconds); each check renews the session, which n8n ends after 15 idle minutes.
- After login the browser goes back to the page it asked for, but only to `https://` on
  `jarllindquist.com` or a subdomain of it.
- `POST /auth/login` and `/auth/logout` only from the page's own origin.

Settings (environment): `N8N_WEBHOOK_URL`, `MAGIC_LINK_APP` (`ops`), `COOKIE_DOMAIN`
(`jarllindquist.com`), `PUBLIC_ORIGIN` (`https://jarllindquist.com`), `OPS_USER` (`admin`, the
name the services see).

## Develop

```bash
pip install -r requirements-dev.txt
pytest -q
```

The tests replace n8n with a fake, so they never send anything to Telegram.

## CI/CD

CI runs the tests, `pip-audit` and starts the image read-only. After a green CI on main, Deploy
builds `passwordnotsafe/auth-gateway`, copies `docker-compose.prod.yml` to `/home/repos/auth-gateway`
and starts it, with the SSH and Docker Hub credentials from Vault (`kv/server-deploy`).
