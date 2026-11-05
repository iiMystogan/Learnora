# Learnora — Onderwijsplatform

This repository contains a demonstrator for a class-based assignment and submission workflow. It is intended for local review and evaluation by education organisations.

## Run from Command Prompt (Windows)

Requirements: **Git**, **Node.js 20+** and **npm**. You do not need to download a ZIP file or manually create/place the project files. Git downloads the selected version and creates its project folder automatically.

Choose which version you want to run.

### Stable version — main

Open Command Prompt and paste:

```cmd
cd /d "%USERPROFILE%"
git clone --branch main --single-branch https://github.com/iiMystogan/Xerte-file-manager.git Learnora-main
cd Learnora-main
npm install
npm run dev
```

### Demo/development version — demo/education-platform

To keep the demo separate from the stable version, open a new Command Prompt window and paste:

```cmd
cd /d "%USERPROFILE%"
git clone --branch demo/education-platform --single-branch https://github.com/iiMystogan/Xerte-file-manager.git Learnora-demo
cd Learnora-demo
npm install
npm run dev
```

When the app starts, open **http://localhost:3000** in your browser. Keep the Command Prompt window open while using the app. Stop it with **Ctrl+C**.

### Start the app again later

After the first setup, you do not need to clone or install again. Open Command Prompt and use the matching commands:

**Stable version:**
```cmd
cd /d "%USERPROFILE%\\Learnora-main"
git pull --ff-only
npm run dev
```

**Demo version:**
```cmd
cd /d "%USERPROFILE%\\Learnora-demo"
git pull --ff-only
npm run dev
```

Only run `npm install` again if project dependencies have changed.

## ICT-productdemonstratie

Volg [de ICT-demo-checklist](security/ICT-DEMO-CHECKLIST.md) voor de demonstratie van beheerder-, docent- en leerlingstromen. Gebruik alleen de lokale demoaccounts hieronder en synthetische gegevens.

## Demo accounts

| Role | Email | Password |
|---|---|---|
| Administrator | admin@demo.local | Admin123! |
| Teacher | docent.jansen@demo.local | Teacher123! |
| Teacher | docent.visser@demo.local | Teacher123! |
| Student | student.noor@demo.local | Student123! |
| Student | student.liam@demo.local | Student123! |
| Student | student.sara@demo.local | Student123! |

The first start seeds these demo accounts and sample classes/assignments only when the users table is empty. Do not use these credentials outside a local demo.

## What is demonstrated

- Separate administrator, teacher and student accounts.
- Teachers are linked to specific classes; students are enrolled in classes.
- Teachers see submissions only for classes they teach. Students see only their own submissions and assignments for their enrolled classes.
- Assignments can be targeted to one or more classes and have instructions and deadlines.
- Students upload PDF, DOC, DOCX or ZIP files (maximum 20 MB) and can replace their submission.
- Teachers can download work and record feedback and a grade/status.
- Administrator overview, account creation and an activity log.
- Server-side permission checks for class, assignment, submission and download routes.

## Important: demo, not production

This is a functional prototype for ICT demonstration, not an approved school service. Security Phase 1 adds automated authorization/session/CSRF checks, upload signature validation, safer downloads, browser security headers and a dependency audit. The current dependency audit reports no known vulnerabilities, and CI runs the automated tests, type checks and frontend build. These checks are not an independent penetration test or an accessibility, load or AVG/privacy assessment. Malware scanning, production backup/recovery, retention, monitoring and deployment readiness still require review. Use only the local demo accounts and synthetic data; do not upload real student work or personal data.

Before any real deployment, involve ICT/security/privacy stakeholders and complete a security and privacy review. Set a strong `JWT_SECRET` (at least 32 characters) and `NODE_ENV=production`; production startup refuses a missing/weak JWT secret. Configure HTTPS, secure file storage, backup/restore, logging, malware scanning, rate limiting and retention before accepting real data.

## Planned Entra ID transition

Authentication is deliberately isolated behind the session/login endpoints. A future Microsoft Entra ID OpenID Connect integration should:
1. Authenticate the user with the organisatie-tenant.
2. Map the immutable Entra tenant/object identity to an internal `users` record (do not use email as the permanent identifier).
3. Keep the platform's role, class membership, assignment and submission authorization in this application's database.
4. Remove local password login and local account provisioning for production, with controlled admin/invitation provisioning.

The current local demo is not yet wired to Entra ID and does not imply that the organisation has approved an app registration.

## API-autorisatie

De route-voor-route rol- en gegevensgrenzen staan in [de API-autorisatiematrix](security/API-AUTHORIZATION.md). De matrix beschrijft ook welke API-routes bewust publiek zijn.

## Network security

See [security/NETWORKING.md](security/NETWORKING.md) for the current private-network inventory, internal-service trust rules, client-IP rate-limit configuration and hosting-portability requirements. Review it before adding services or changing the hosting provider.

## Sessie-invalidatie

Bij wijzigingen van gebruikersrol, accountstatus of wachtwoord worden alle bestaande sessies van het betreffende account ingetrokken. Gebruikers kunnen ook zelf hun wachtwoord wijzigen door hun huidige wachtwoord te bevestigen; daarna moeten ze opnieuw inloggen. De beheerder kan accounts beheren via de gebruikerspagina. Zie [security/SESSIONS.md](security/SESSIONS.md) voor details.

## Wachtwoordbeleid

Nieuwe accounts en wachtwoordwijzigingen vereisen minimaal 12 tekens en maximaal 1024 UTF-8-bytes. Lange wachtwoordzinnen zijn toegestaan; er is geen verplichte combinatie van hoofdletters, cijfers of symbolen. Een lokale denylist blokkeert daarnaast een aantal bekende, veelgebruikte wachtwoorden en eenvoudige patronen. Bestaande demo-accounts behouden hun huidige wachtwoord totdat dat wordt gewijzigd. Zie [security/PASSWORDS.md](security/PASSWORDS.md).

## Wachtwoordherstel

Selfservice-wachtwoordherstel via e-mail is nog niet ingeschakeld, omdat er geen e-mailprovider of geverifieerde afzender is geconfigureerd. Een beheerder kan voorlopig een nieuw wachtwoord instellen; daarbij worden alle bestaande sessies ingetrokken. Zie [security/PASSWORD-RESET.md](security/PASSWORD-RESET.md) voor de veilige ontwerpvoorwaarden voordat e-mailherstel wordt toegevoegd.

## XSS-audit en bestandsbeveiliging

De frontend gebruikt React-tekstweergave en bevat geen gevonden raw-HTML-sinks zoals `dangerouslySetInnerHTML` of `innerHTML`. Regressietests bewaken deze bevinding. Uploads worden naast de extensie ook op hun bestandsheader gecontroleerd; downloads worden als geïsoleerde bijlage geserveerd. Deze controles zijn geen vervanging voor malware-scanning of volledige bestandsvalidatie. Zie [security/XSS.md](security/XSS.md) en [security/UPLOADS.md](security/UPLOADS.md).

## HTTP-beveiligingsheaders

Learnora stuurt browserbeveiligingsheaders voor MIME-type bescherming, clickjacking, referrerbeleid en browserrechten. De Content Security Policy staat bewust eerst in `Report-Only`-modus, zodat compatibiliteit met de bestaande UI kan worden gecontroleerd voordat bronnen eventueel worden geblokkeerd. HSTS wordt alleen in productie toegevoegd. Zie [security/HTTP-HEADERS.md](security/HTTP-HEADERS.md) voor de policy en de stappen vóór afdwinging.

## CSRF-bescherming

Alle API-verzoeken die gegevens wijzigen (zoals POST, PUT, PATCH en DELETE) vereisen een geldig, ondertekend CSRF-token. De frontend haalt dit token op via `GET /api/csrf` en stuurt het bij mutaties mee in de header `X-CSRF-Token`. Het token moet overeenkomen met de host-only `learnora_csrf`-cookie. De handtekening wordt met `JWT_SECRET` gecontroleerd; het token wordt niet als authenticatiemiddel gebruikt.

GET-, HEAD- en OPTIONS-verzoeken zijn vrijgesteld. De sessiecookie blijft HttpOnly en wordt niet door JavaScript gelezen. Zie [security/CSRF.md](security/CSRF.md) voor de implementatie en testdekking.
