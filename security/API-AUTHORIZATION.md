# API-autorisatiematrix

Gecontroleerd op branch `security/phase-1-backend`. Elke gegevensroute heeft een authenticatie- en autorisatiegrens; de uitzonderingen zijn de publieke CSRF-bootstrap en login, plus logout dat een bestaande sessie intrekt of de cookie opruimt. Muterende API-verzoeken vallen onder de centrale CSRF-controle.

| Endpoint | Toegang | Gegevensgrens / controle |
|---|---|---|
| `GET /api/csrf` | Publiek | Geeft een ondertekend CSRF-token uit; bevat geen accountgegevens. |
| `POST /api/login` | Publiek | Generieke foutmelding, rate limiting en sessie aanmaken na geldige credentials; de actieve organisatie komt uit een gecontroleerd lidmaatschap. |
| `GET /api/organizations` | Ingelogde gebruiker | Geeft uitsluitend de eigen actieve lidmaatschappen terug; antwoord is niet cachebaar. |
| `POST /api/organization/switch` | Ingelogde gebruiker + CSRF-token | Wisselt alleen naar een actieve organisatie waarvan de gebruiker lid is; werkt de bestaande sessiecontext atomair bij en schrijft een auditregel. |
| `POST /api/logout` | CSRF-token vereist | Trekt de sessie in als die geldig is en wist de cookie; werkt ook om een verlopen of ongeldige cookie op te ruimen. |
| `GET /api/me` | Ingelogde gebruiker | Geeft uitsluitend de eigen accountidentiteit terug. |
| `POST /api/account/password` | Ingelogde gebruiker | Wijzigt alleen het eigen wachtwoord na controle van het huidige wachtwoord; trekt sessies in. |
| `GET /api/dashboard` | Ingelogde gebruiker | Admin: platformoverzicht; docent: eigen klassen; student: eigen klassen en gepubliceerde opdrachten. |
| `GET /api/classes` | Ingelogde gebruiker | Admin: alle klassen; docent: toegewezen klassen; student: ingeschreven klassen. |
| `POST /api/classes` | Admin of docent | Docent wordt zelf aan de nieuwe klas gekoppeld; admin kan alleen een bestaand actief docent toewijzen. |
| `GET /api/classes/:id/students` | Admin of docent | Docent alleen voor een eigen klas; admin voor alle klassen. |
| `POST /api/classes/:id/students` | Admin of docent | Docent alleen voor een eigen klas; alleen studentaccounts kunnen worden ingeschreven. |
| `GET /api/assignments` | Ingelogde gebruiker | Admin: alle opdrachten; docent: opdrachten gekoppeld aan eigen klassen; student: gepubliceerde opdrachten uit eigen klassen. |
| `POST /api/assignments` | Admin of docent | Docent mag alleen eigen klassen koppelen; elke klas-ID wordt gevalideerd. |
| `DELETE /api/assignments/:id` | Admin of docent | Docent mag verwijderen als alle gekoppelde klassen van die docent zijn. |
| `GET /api/assignments/:id/progress` | Admin of docent | Docent ziet alleen leerlingen en inzendingen uit eigen gekoppelde klassen; student is geweigerd. |
| `GET /api/submissions` | Ingelogde gebruiker | Admin: alle; docent: eigen klassen; student: alleen eigen inzendingen. |
| `POST /api/assignments/:id/submit` | Student | Alleen een gepubliceerde opdracht uit een eigen klas; controle vóór upload én direct vóór database-opslag. |
| `POST /api/submissions/:id/feedback` | Admin of docent | Docent alleen als de student en opdracht binnen een eigen klas vallen. |
| `GET /api/submissions/:id/download` | Ingelogde gebruiker | Admin; de eigenaar-student; of een docent uit de klas van die student en opdracht. |
| `GET /api/admin/overview` | Alleen admin | Dashboardgegevens zijn uitsluitend voor beheerders. |
| `GET /api/admin/users` | Alleen admin | Beheerderslijst is uitsluitend voor beheerders. |
| `PATCH /api/admin/users/:id` | Alleen admin | Rol/status/wachtwoord valideren; relevante sessies intrekken; eigen admin niet uit de rol kunnen verwijderen of deactiveren. |
| `POST /api/admin/users` | Alleen admin | Beheerders kunnen accounts met gevalideerde rol en wachtwoord aanmaken. |
| `GET /api/admin/audit` | Alleen admin | Activiteitenlog is uitsluitend voor beheerders. |
| Onbekende `/api/*`-route | Geen | Geeft JSON 404 terug; er is geen alternatieve publieke API-handler. |

## Testdekking

- `tests/authorization.test.ts`: regressietests voor inzendingen, opdrachten en docentdashboards.
- `tests/http.integration.test.ts`: HTTP-controles voor de rollen admin/docent/student, klassen, opdrachten, inzendingen, feedback, downloads, organisatiekeuze en -wisseling, en ongeldige of ongeautoriseerde verzoeken.

De autorisatiecontrole behandelt elke API-route in de huidige `server.ts`. De aangrenzende invoervalidatie-, transacties-, bestandsvervangings- en demo-seedingreviews blijven afzonderlijke Phase 1-onderwerpen.
