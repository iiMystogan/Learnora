# HTTP-beveiligingsheaders en CSP

## Doel

Learnora voegt browsergerichte beveiligingsheaders toe als extra verdedigingslaag tegen onder meer MIME-type verwarring, clickjacking, onnodige referrer-lekkage en ongewenst gebruik van browsermogelijkheden.

Deze headers zijn aanvullend. Ze vervangen geen authenticatie, autorisatie, output-escaping, veilige bestandsverwerking of CSRF-bescherming.

## Actieve headers

- `X-Content-Type-Options: nosniff` voorkomt dat browsers contenttypes proberen te raden.
- `X-Frame-Options: DENY` voorkomt dat Learnora in een frame wordt geladen.
- `Referrer-Policy: strict-origin-when-cross-origin` beperkt referrer-informatie bij externe navigatie.
- `Permissions-Policy` schakelt camera, microfoon en geolocatie uit zolang Learnora die browsermogelijkheden niet nodig heeft.
- In productie wordt `Strict-Transport-Security: max-age=15552000` toegevoegd. Dit instrueert browsers om Learnora gedurende zes maanden via HTTPS te benaderen. De header wordt niet in lokale/testomgevingen gezet.

## Content Security Policy: eerst observeren

Learnora stuurt voorlopig `Content-Security-Policy-Report-Only`, niet de afdwingende `Content-Security-Policy`-header. De browser kan overtredingen signaleren in de ontwikkelaarstools, maar blokkeert de betreffende bronnen nog niet.

De huidige policy staat alleen de eigen origin toe voor scripts en verbindingen. Voor de bestaande vormgeving zijn styles van Google Fonts en fonts van Google Fonts toegestaan. Inline styles zijn voorlopig toegestaan om compatibiliteit met de bestaande UI te behouden. Afbeeldingen zijn beperkt tot de eigen origin, data- en blob-URL's.

Er is nog geen CSP-rapportage-endpoint geconfigureerd. Controleer browserconsolemeldingen en de productie-preview voordat CSP ooit afdwingend wordt gemaakt. Voeg geen externe origins toe zonder vast te stellen waarom Learnora ze nodig heeft.

## Vervolg voordat CSP wordt afgedwongen

1. Controleer de Report-Only-meldingen in de lokale omgeving en een representatieve productie-preview.
2. Test alle rollen, uploads/downloads, Google Fonts en alle relevante pagina's.
3. Controleer expliciet toekomstige Entra ID-login, redirect- en logoutflows zodra die integratie wordt ontworpen. De huidige `connect-src 'self'`-regel is bewust beperkt; eventuele identity-provider endpoints moeten pas worden toegevoegd op basis van de gekozen Entra ID-flow.
4. Verwijder waar mogelijk inline styles en verscherp de policy.
5. Schakel afdwinging pas in na expliciete compatibiliteitstests.

## Portabiliteit en Entra ID

De headers worden in Express ingesteld en zijn niet gekoppeld aan Railway. Ze gelden voor zowel API-antwoorden als de frontend, ongeacht de uiteindelijke hostingprovider.

De policy is bewust nog niet afgestemd op een specifieke Entra ID-tenant of OAuth/OIDC-implementatie. Wanneer Entra ID wordt toegevoegd, moeten de benodigde identity-provider origins, redirects en eventuele popup-/iframe-eisen afzonderlijk worden beoordeeld. Verbreed de policy niet preventief.

## Tests

De HTTP-integratietest controleert de aanwezigheid en waarden van de basisheaders en bevestigt dat CSP in de huidige fase report-only blijft. HSTS wordt alleen in productie toegevoegd en is daarom niet actief in de testomgeving.
