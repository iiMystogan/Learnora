# CSRF-bescherming

## Doel

Learnora gebruikt een HttpOnly-sessiecookie voor authenticatie. Browsers sturen cookies automatisch mee; daarom moet de API bij elk verzoek dat servergegevens wijzigt controleren of het verzoek bewust vanuit de Learnora-frontend is gestart.

## Werking

- `GET /api/csrf` maakt een cryptografisch willekeurige nonce en ondertekent deze met HMAC-SHA256 op basis van `JWT_SECRET`.
- De ondertekende waarde wordt teruggegeven aan de frontend en geplaatst in de host-only cookie `learnora_csrf`.
- De CSRF-cookie is bewust niet HttpOnly, zodat de frontend de waarde kan lezen. De cookie gebruikt `SameSite=Lax`, `Path=/`, een geldigheidsduur van acht uur en `Secure` in productie.
- De frontend stuurt bij POST-, PUT-, PATCH- en DELETE-verzoeken dezelfde waarde mee in `X-CSRF-Token`.
- De server controleert de HMAC-handtekening en vergelijkt header en cookie met een timing-veilige vergelijking.
- Ontbrekende, ongeldige of afwijkende tokens geven HTTP 403.
- GET-, HEAD- en OPTIONS-verzoeken zijn vrijgesteld. De sessiecookie blijft HttpOnly.

## Beveiligingsgrenzen

Het CSRF-token is geen authenticatiemiddel en vervangt de sessiecontrole of autorisatie niet. Het token wordt niet in localStorage of sessionStorage opgeslagen. De CSRF-cookie krijgt geen Domain-attribuut en is daardoor host-only. De API configureert geen permissieve CORS-regels; voeg die niet toe zonder de CSRF- en originstrategie opnieuw te beoordelen.

De beveiliging vertrouwt op de same-origin-beperkingen van browsers, de custom request-header en de niet te vervalsen HMAC-handtekening. XSS op de Learnora-origin kan CSRF-bescherming omzeilen en moet afzonderlijk worden voorkomen.

## Tests

De HTTP-integratietest controleert onder meer:
- de CSRF-bootstrap en cookie-eigenschappen;
- afwijzing van login zonder token of met een ongeldig token;
- succesvolle login met een geldig token;
- afwijzing van logout zonder token, waarbij de sessie actief blijft;
- bestaande autorisatie- en endpointtests met de CSRF-header.

## Beheer

Er is geen extra omgevingsvariabele nodig. `JWT_SECRET` moet geheim blijven en in productie minimaal 32 tekens bevatten. Bij rotatie van `JWT_SECRET` worden zowel JWT-sessies als CSRF-handtekeningen ongeldig; gebruikers moeten dan opnieuw inloggen en de CSRF-token opnieuw ophalen.
