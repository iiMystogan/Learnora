# XSS-audit en veilige frontend-weergave

## Bevindingen

De huidige React-interface gebruikt JSX-tekstinterpolatie voor namen, e-mailadressen, opdrachtomschrijvingen, bestandsnamen en feedback. React escaped deze waarden standaard voordat ze als tekst in de DOM worden geplaatst.

Tijdens de audit zijn in `src/App.tsx` geen toepassingen gevonden van:
- `dangerouslySetInnerHTML`
- `innerHTML` of `outerHTML` als HTML-schrijfmechanisme
- `document.write`
- `eval()` of `new Function()`

Er is daarom geen HTML-sanitizer toegevoegd: Learnora heeft op dit moment geen functie nodig die door gebruikers aangeleverde HTML als actieve markup moet tonen. Sanitization is geen vervanging voor het vermijden van onveilige HTML-sinks.

## Regressiebewaking

`tests/xss-regression.test.ts` controleert dat de frontend geen van de hierboven genoemde risicovolle sinks introduceert. Dit is een gerichte guardrail, geen volledige geautomatiseerde XSS-analyse. Nieuwe frontendmodules en componenten moeten bij toekomstige audits ook worden gecontroleerd.

## Richtlijnen voor toekomstige ontwikkeling

- Render door gebruikers aangeleverde tekst via normale React-interpolatie.
- Voeg geen `dangerouslySetInnerHTML` toe zonder expliciete security review en een passende, onderhouden sanitizer.
- Bouw geen HTML-string op basis van gebruikersinvoer.
- Valideer URL's en bestemmingen afzonderlijk wanneer in de toekomst links of externe media worden ondersteund.
- Behandel geüploade bestanden als onbetrouwbare content; serveer ze als download en niet als actieve webcontent.

## Entra ID

Deze maatregelen zijn onafhankelijk van de authenticatieprovider. Wanneer Entra ID wordt toegevoegd, blijven XSS-bescherming en veilige rendering voor alle rollen en identiteiten noodzakelijk.
