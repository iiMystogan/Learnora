# Wachtwoordbeleid

## Regels

Nieuwe wachtwoorden en wachtwoordwijzigingen moeten voldoen aan dezelfde backendcontrole:

- Minimaal 12 Unicode-tekens.
- Maximaal 1024 UTF-8-bytes.
- Geen verplichte mix van hoofdletters, kleine letters, cijfers of symbolen; lange wachtwoordzinnen zijn toegestaan.
- De limiet wordt gecontroleerd vóór het hashen met bcrypt.

De regels gelden voor accountaanmaak door een beheerder, het aanmaken van een studentaccount vanuit een klas en wachtwoordwijzigingen door een beheerder. Een bestaand account dat via een eerdere versie een korter wachtwoord heeft, kan voorlopig nog inloggen; de nieuwe regels gelden zodra een nieuw wachtwoord wordt ingesteld.

## Waarom geen verplichte tekencombinatie?

Een minimale lengte en ruimte voor wachtwoordzinnen stimuleren langere wachtwoorden zonder gebruikers te dwingen voorspelbare patronen zoals hoofdletter + cijfer + uitroepteken te gebruiken. Een controle op veelgebruikte of gecompromitteerde wachtwoorden is een afzonderlijke vervolgstap.

## Tests

De HTTP-integratietests controleren dat een wachtwoord van 11 tekens wordt geweigerd bij accountaanmaak en bij een beheerder-wachtwoordwijziging, terwijl bestaande testwachtwoorden van minimaal 12 tekens worden geaccepteerd.
