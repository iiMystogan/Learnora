# Sessie-invalidatie bij accountwijzigingen

## Doel

Een accountwijziging mag geen bestaande ingelogde sessies laten voortbestaan met verouderde rechten of een oud wachtwoord.

## Gedrag

De beheerder kan via `PATCH /api/admin/users/:id` de rol, accountstatus en/of het wachtwoord aanpassen. Alleen expliciet opgegeven velden worden gewijzigd. Rollen zijn beperkt tot `admin`, `teacher` en `student`; accountstatus moet een boolean zijn. Een nieuw wachtwoord moet minimaal 12 tekens en maximaal 1024 UTF-8-bytes bevatten; zie [Wachtwoordbeleid](./PASSWORDS.md).

Na iedere daadwerkelijke wijziging worden binnen dezelfde SQLite-transactie alle actieve sessies van het doelaccount ingetrokken. De huidige sessie van de beheerder wordt eveneens ingetrokken als die diens eigen wachtwoord wijzigt; de server wist dan de sessiecookie en de frontend vraagt opnieuw om in te loggen.

Een gedeactiveerd account kan niet authenticeren. Bij latere heractivering blijven eerder ingetrokken sessies ingetrokken: de gebruiker moet opnieuw inloggen. Een beheerder kan zichzelf niet deactiveren of de eigen beheerdersrol verwijderen om onbedoelde uitsluiting van beheer te voorkomen.

De actie wordt vastgelegd in de auditlog als `user.security_updated`. Er wordt geen wachtwoord of wachtwoordhash in de auditdetails opgeslagen.

## Validatie en tests

De HTTP-integratietests controleren sessie-intrekking bij rolwijziging, wachtwoordwijziging en deactivering, inclusief parallelle sessies. Ze controleren ook dat heractivering oude sessies niet herstelt, ongeldige invoer wordt geweigerd en een beheerder zichzelf niet kan deactiveren.

## Grenzen

De huidige demo-omgeving gebruikt lokale wachtwoordaccounts. Bij toekomstige externe identity-providerintegratie moet sessie-intrekking ook worden afgestemd op de provider (bijvoorbeeld refresh tokens en provider-side sessions). Deze implementatie trekt Learnora-sessies in de eigen database in.
