# Wachtwoordherstel

## Status

Een selfservice-reset via e-mail is bewust nog niet geïmplementeerd. In deze repository is geen e-mailprovider, SMTP-configuratie of geverifieerde afzender ingericht. Een resetlink genereren zonder betrouwbaar en gecontroleerd afleverkanaal zou geen veilige herstelprocedure opleveren.

## Huidige herstelmogelijkheid

Een beheerder kan in de gebruikersbeheerpagina een nieuw wachtwoord instellen. Die wijziging:

- gebruikt dezelfde wachtwoordlengte- en denylistcontrole;
- trekt alle bestaande sessies van het account in;
- vereist dat de gebruiker opnieuw inlogt;
- wordt in de auditlog vastgelegd zonder het wachtwoord of de hash op te slaan.

Het nieuwe wachtwoord moet via een vooraf afgesproken, passend beveiligd kanaal aan de gebruiker worden overgedragen. Gebruik geen gedeelde openbare kanalen.

## Vereisten voordat selfservice-herstel wordt gebouwd

1. Kies en configureer een e-mailprovider met een geverifieerd afzenderdomein en bewaakte afleverstatus.
2. Gebruik een cryptografisch willekeurig resettoken van minimaal 256 bits; sla alleen een hash van het token op.
3. Maak tokens eenmalig bruikbaar, laat ze na maximaal 15 minuten verlopen en trek oudere tokens in zodra een nieuw token wordt uitgegeven.
4. Geef geen informatie prijs over het bestaan of de status van een e-mailadres; gebruik generieke publieke reacties en rate limiting.
5. Bouw resetlinks uitsluitend op basis van een vaste, geconfigureerde applicatie-URL. Log nooit resettokens en voorkom dat ze via referrer-headers uitlekken.
6. Na een geslaagde reset moeten alle actieve sessies worden ingetrokken en moet het nieuwe wachtwoord dezelfde beleidscontrole doorlopen.
7. Test tokenverval, hergebruik, brute-force-beperking, accountstatus, sessie-intrekking en mislukte e-mailaflevering.

Totdat deze randvoorwaarden geregeld zijn, blijft resetten via een beheerder de ondersteunde herstelroute.
