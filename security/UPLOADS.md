# Beveiliging van inzendingen en downloads

## Uploadcontroles

Learnora accepteert alleen de extensies PDF, DOC, DOCX en ZIP en hanteert een maximale uploadgrootte van 20 MB. De server genereert zelf een willekeurige opslagnaam; de oorspronkelijke bestandsnaam wordt alleen als metadata bewaard. De standaardopslag staat buiten de publiek geserveerde webroot. Startup weigert een `UPLOAD_DIR` die binnen de Vite-webroot (development) of de statische `dist`-map (production) ligt; directe `/uploads/...`-URL's worden geweigerd. Bestanden zijn alleen bereikbaar via de geautoriseerde downloadroute.

Naast de extensie controleert `security/upload-validation.ts` nu ook de bestandsheader:
- PDF: zoekt naar de PDF-signatuur in de eerste 1024 bytes.
- DOC: controleert de OLE Compound File-signatuur.
- DOCX en ZIP: controleren op een geldige bekende ZIP-header.

Een mismatch wordt geweigerd en het tijdelijk opgeslagen bestand wordt verwijderd.

## Beperkingen

Deze headercontrole is een lichte formaatcontrole, geen volledige parser, malwarecontrole of garantie dat een bestand veilig is. DOCX wordt op ZIP-container-signatuur gecontroleerd, niet op alle interne Office-onderdelen. ZIP-bestanden kunnen bovendien inhoud bevatten die schadelijk is wanneer de gebruiker die later uitpakt of opent.

Voordat Learnora echte studentbestanden verwerkt, zijn aanvullende maatregelen nodig, waaronder malware-scanning, retentiebeleid, opslagisolatie, back-ups en een privacy/security-review.

## Downloads

Downloads blijven achter authenticatie en bestaande autorisatiecontroles. De server levert ze als attachment en voegt voor downloadantwoorden toe:
- `X-Content-Type-Options: nosniff`
- `Content-Security-Policy: sandbox; default-src 'none'`
- `Cross-Origin-Resource-Policy: same-origin`
- `Cache-Control: private, no-store`

Hierdoor worden bestanden niet bedoeld als actieve Learnora-pagina's weergegeven en worden ze niet publiek cachebaar gemaakt.

## Entra ID

De upload- en downloadautorisatie blijft gebaseerd op Learnora's interne gebruiker, rol en klasrelaties. Een toekomstige Entra ID-login vervangt de authenticatie, niet deze object- en klasautorisatie. Gebruik daarom geen e-mailadres als permanente bestands- of eigenaarssleutel.
