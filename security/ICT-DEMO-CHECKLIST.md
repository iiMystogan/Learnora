# ICT-productdemonstratie — checklist

## Doel
Laat met de lokale demo zien hoe beheerder-, docent- en leerlingaccounts samenwerken in de opdracht- en inzendingsstroom. Dit is een productdemonstratie op de aparte branch `security/phase-1-backend`; geen productieacceptatie.

## Voorbereiding
- [ ] Start de lokale kopie van `security/phase-1-backend` volgens de Windows-stappen in de README.
- [ ] Gebruik een geïsoleerde demo-installatie met een lege database zodat de voorbeeldaccounts en voorbeeldklassen worden aangemaakt. Laat bestaande lokale databasebestanden ongemoeid.
- [ ] Open de website op de lokale URL die de terminal meldt.
- [ ] Gebruik uitsluitend de demoaccounts uit de README en verzonnen namen, opdrachten en bestanden.
- [ ] Houd deze checklist en de README met de demoaccounts bij de hand.

## Demonstratiescenario

### 1. Beheerder
- [ ] Meld aan met het beheerdersaccount uit de README.
- [ ] Toon het beheerdersoverzicht, de voorbeeldklassen en opdrachten.
- [ ] Toon het aanmaken en beheren van een account en het activiteitenlog.
- [ ] Bevestig dat een rol- of accountwijziging bestaande sessies van dat account intrekt.

### 2. Docent
- [ ] Meld aan als docent Jansen en toon diens klassen en opdrachten.
- [ ] Toon dat inzendingen alleen zichtbaar zijn voor een docent die bij de betreffende klas hoort.
- [ ] Download een testinzending en voeg feedback of een beoordeling toe.
- [ ] Meld daarna aan als docent Visser en toon dat diens toegang tot de klassen van Jansen ontbreekt.

### 3. Leerling
- [ ] Meld aan als leerling Noor en toon alleen diens eigen inzendingen en opdrachten van de eigen klassen.
- [ ] Dien een synthetisch PDF-, DOC-, DOCX- of ZIP-bestand in.
- [ ] Vervang de eigen inzending en laat zien dat een andere leerling die niet kan openen.
- [ ] Toon dat een bestand met bijvoorbeeld een `.pdf`-extensie maar gewone tekstinhoud wordt geweigerd.

### 4. Beveiligingsgedrag
- [ ] Toon dat uitloggen de sessie beëindigt en dat een volgende beschermde pagina opnieuw aanmelden vereist.
- [ ] Toon de browserbeveiligingsheaders en de CSP in Report-Only-modus, indien ICT dit wil bekijken.
- [ ] Benoem dat uploads op formaatkenmerken worden gecontroleerd, maar dat dit geen malware-scanning is.

## Vastleggen van feedback
- [ ] Noteer welke gebruikersstroom ICT als compleet en bruikbaar beschouwt.
- [ ] Noteer ontbrekende functies, fouten, toegankelijkheidsvragen en beheerwensen.
- [ ] Noteer eisen voor gegevensopslag, bewaartermijnen, back-ups, logging, privacy en beheer.
- [ ] Leg per punt een eigenaar en prioriteit vast voordat productiegeschiktheid wordt beoordeeld.

## Grenzen van deze demo
- Gebruik geen echte leerlinggegevens of echt leerlingwerk.
- De demoaccounts zijn alleen bedoeld voor lokaal testen; gebruik deze wachtwoorden nergens anders.
- De lokale login blijft beschikbaar in deze demonstrator. Microsoft Entra ID is bewust nog niet aangesloten.
- De CI-tests en dependency-audit zijn geslaagd, maar vervangen geen onafhankelijke penetratietest, toegankelijkheidsonderzoek, loadtest of AVG/privacybeoordeling.
- Deze demo is geen productieomgeving en geeft geen productie-goedkeuring.

## Volgorde na de demonstratie
1. Verwerk ICT-feedback en maak de product- en operationele eisen concreet.
2. Werk de benodigde product-, privacy-, toegankelijkheids- en beheerpunten af.
3. Bepaal samen met ICT of de applicatie klaar is voor een productiebeoordeling.
4. **Microsoft Entra ID blijft de laatste checkliststap**, nadat de demonstrator is beoordeeld en de benodigde productkeuzes zijn vastgesteld.
