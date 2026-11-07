# Laborator de analiză a securității rețelelor

## Configurație și scop

Laboratorul de hackathon folosește un hotspot iPhone și trei laptopuri conectate
la acesta: două Mac-uri și un Windows. Ping-ul între laptopuri funcționează,
conform verificării raportate de echipă. Aceasta este o observație de
conectivitate, nu o garanție că toate porturile sau serviciile sunt accesibile.

Adresele IP și masca/prefixul de rețea se verifică la fiecare sesiune, pe
interfața conectată la hotspot. Nu presupunem o adresă sau o mască permanentă
și nu deducem subrețeaua din adresa unui singur host. Asocierea dintre
adrese și laptopuri trebuie consemnată din nou după reconectare.

## Test preliminar HTTP 

Artefact: [`preliminary/http_test.xml`](preliminary/http_test.xml).
Este un raport XML Nmap, nu o captură de pachete. Copia păstrează exact
conținutul originalului `/Users/antonia/http_test.xml`; originalul nu a fost
modificat.

Comanda înregistrată în XML (istorică, nu o țintă permanentă):

```sh
nmap -Pn -sV --script http-title -p 8080 -oX http_test.xml 172.20.10.3
```

| Câmp | Observație în raport |
| --- | --- |
| Instrument | Nmap 7.993, scanare TCP connect |
| Țintă la momentul testului | `172.20.10.3`, TCP `8080` |
| Stare port | `open`, motiv `syn-ack` |
| Serviciu detectat | HTTP, `SimpleHTTPServer 0.6`, `Python 3.14.3` |
| Antet server raportat | `SimpleHTTP/0.6 Python/3.14.3` |
| Titlu HTTP | `Admin Login` |
| Hostname | Lista `hostnames` este goală |
| MAC și vendor MAC | Nu sunt prezente în XML |
| Rezultat execuție | Succes, o adresă scanată, durată 6,83 secunde |

Cu `-Pn`, starea hostului `up` are motivul `user-set`; nu reprezintă o
verificare ICMP în acest raport. Portul deschis și răspunsul HTTP sunt
observațiile de serviciu. Verificarea ping raportată de echipă este separată.

Titlul „Admin Login” nu dovedește existența unei autentificări funcționale,
a unor credențiale implicite sau a unei vulnerabilități. Identificarea
serviciului și versiunile sunt cele raportate de Nmap, fără verificare locală
suplimentară. Absența hostname-ului și a vendorului MAC în raport înseamnă
date indisponibile, nu absența acestor proprietăți pe dispozitiv. Raportul nu
identifică sigur care laptop a găzduit serviciul.

SHA-256 al originalului și al copiei:

```text
56d333f6d95a6b55e1ca349d228b6c4ab3f30384526708e8e572d354557bde7e
```

## Organizarea și reluarea experimentelor

- `preliminary/`: testul inițial de conectivitate HTTP și colectare Nmap;
  nu este o măsurătoare înainte/după remediere.
- `before/`: rezervat măsurătorilor înainte de modificările experimentului.
- `after/`: rezervat măsurătorilor după modificări, cu condiții comparabile.

Pentru fiecare sesiune, consemnați data, laptopul care scanează, laptopul țintă,
interfețele, IP-urile și măștile/prefixele curente, serviciile pornite și
schimbările relevante de firewall. Folosiți doar țintele autorizate ale
laboratorului și salvați rezultatele noi în fișiere distincte, fără a
suprascrie acest artefact. Comparațiile înainte/după trebuie să urmărească
același dispozitiv și serviciu, chiar dacă adresa IP se schimbă.

## BEFORE -> remediere -> AFTER

Instrumentul oficial de captură folosește aceleași guardrail-uri ca `scan` și
nu poate porni fără confirmare explicită:

```sh
python -m netcheck lab-run --label before <IP-or-CIDR> --confirm
```

Pentru mai multe ținte autorizate, repetați argumentul pozițional în aceeași
comandă. Fiecare rezultat primește un XML UUID în `lab/before/` și un JSON cu
data UTC, laptopul scanner, ținta, durata, numărul de adrese și rețeaua
detectată. `after` se capturează identic:

```sh
python -m netcheck lab-run --label after <IP-or-CIDR> --confirm
```

Nu se suprascrie niciun rezultat existent. Durata unei scanări pe un hotspot
mic nu dovedește că un `/24` a fost scanat în mai puțin de cinci minute;
această performanță rămâne de măsurat pe laptop și rețeaua reale.

1. Verificați manual hotspot-ul, interfața, IP-urile și permisiunea.
2. Porniți serviciile de laborator și salvați `before`.
3. Rulați scriptul de remediere de pe laptopul gazdă:
   - Windows: `.\scripts\windows\remediate-lab-services.ps1`
   - macOS: `zsh scripts/macos/remediate-lab-services.zsh`
4. Verificați că TCP 23 (Telnet) și TCP 1883 (MQTT) nu mai sunt accesibile.
5. Salvați `after` cu aceeași țintă și condiții comparabile.
6. Comparați XML-urile:

```sh
python lab/compare.py lab/before lab/after
```

Comparația folosește exclusiv `lab/services/check_xml.py` pentru
`HTTP_ADMIN_CLEARTEXT`, `DB_EXPOSED`, `MQTT_EXPOSED`, `TELNET_OPEN` și
`FTP_CLEARTEXT`. Integrarea cu analizorul și calculul scorului sunt **TODO**
până când există comanda `analyze`; nu inventăm findings și nu calculăm scorul
manual. Criteriul „gata” este: cel puțin două findings rezolvate și scor mai
bun calculat de motorul oficial. În starea actuală criteriul nu poate fi
declarat atins.

Scripturile opresc doar simulatorul și serviciul MQTT, nu șterg configurații
sau volume; pornirea originală este reversibilă prin reluarea comenzilor
documentate în `lab/services/README.md`. Pe Windows scriptul salvează
procesele locale găsite, iar în Compose oprește serviciile `simulators` și
`mqtt`. Pe macOS salvează PID-urile și trimite simulatorului `TERM`.
Verificarea porturilor este manuală:

```powershell
Test-NetConnection <IP-gazdă> -Port 23
Test-NetConnection <IP-gazdă> -Port 1883
```

```sh
nc -vz <IP-gazdă> 23
nc -vz <IP-gazdă> 1883
```

Rezultatul trebuie consemnat ca eșec de conectare/refuz. Comportamentul exact
al firewall-ului, Nmap, Npcap și regulilor sudoers este neverificat aici și
trebuie confirmat pe laptopurile reale.

## Inventarul sesiunii

Date comunicate de echipă la 7 noiembrie 2026; nu au fost măsurate automat.
Ora verificării rețelei nu a fost comunicată. Hotspot iPhone: **RSH-REXA**.
Identificatorii Laptop 1–3 sunt etichetele echipei, nu hostname-uri detectate.

| Laptop | Sistem | Rol | IP raportat în sesiune | Interfață | Mască/prefix |
| --- | --- | --- | --- | --- | --- |
| Laptop 1 | macOS | Scanner | `172.20.10.2` | De verificat | De verificat |
| Laptop 2 | Windows | Gazdă HTTP, TCP 8080 | `172.20.10.3` | De verificat | De verificat |
| Laptop 3 | macOS | Participant; rol suplimentar nespecificat | `172.20.10.4` | De verificat | De verificat |

Laptop scanner ales: **Laptop 1 (macOS)**.

### Detectarea automată pe scanner

Verificare nativă efectuată la 7 noiembrie 2026 pe laptopul macOS din
workspace, prin `detect_network()`, fără executarea unei scanări:

```python
NetworkInfo(interface='en0', ip='172.20.10.2', prefix_length=28,
            subnet='172.20.10.0/28', gateway='172.20.10.1')
```

Rezultatul corespunde configurației citite prin `ifconfig -a` (mască
`0xfffffff0`) și `netstat -rn -f inet` (gateway implicit pe `en0`).
Prefixul și subnetul sunt calculate din masca reală, nu din tipul hotspot-ului.
Detectarea este implementată pentru **macOS, Windows și Linux**, cu același
contract `detect_network() -> NetworkInfo` și selecție automată a backendului.

| Sistem | Cerințe pentru detectare |
| --- | --- |
| macOS | Utilitarele native `/sbin/ifconfig` și `/usr/sbin/netstat` |
| Windows | Windows PowerShell, modulele NetTCPIP și NetAdapter |
| Linux | `iproute2` cu suport JSON și `/sys/class/net` disponibil |

Python minim: 3.10. Nmap nu este necesar pentru detectare. Windows folosește
[Get-NetIPAddress](https://learn.microsoft.com/powershell/module/nettcpip/get-netipaddress)
și export JSON; Linux folosește
[ip -j](https://man7.org/linux/man-pages/man8/ip.8.html), evitând parsarea
tabelelor localizate. Alte sisteme (de exemplu BSD) produc o eroare explicită.
WSL, containerele și mașinile virtuale nu sunt echivalente cu accesul direct
la hotspot: interfețele virtuale pot fi refuzate intenționat.

Platforma verificată pe laptopul laboratorului este **macOS**. Workflow-ul
`.github/workflows/network-platforms.yml` configurează teste pe macOS,
Windows și Ubuntu, cu Python 3.10 și 3.13. Include teste simulate și un test
nativ pentru citirea/parsarea configurației, fără scanare. Runner-ele cu
rețele ambigue pot fi refuzate în mod valid; erorile comenzilor sau datele
native neinterpretabile fac testul să eșueze. Configurarea workflow-ului nu
înseamnă că acesta a fost deja executat. Verificarea reușită pe laptopuri
Windows/Linux conectate la laborator rămâne necesară pentru demonstrație.

Reverificare din rădăcina repository-ului, fără scanare:

```sh
.venv/bin/python -c 'from netcheck.scanner import detect_network; print(detect_network())'
```

Funcția ridică `NetworkDetectionError` la lipsa conexiunii/gateway-ului,
mai multe adrese sau interfețe LAN active, VPN IPv4/interfețe virtuale ori
rute ambigue sau invalide. Nu alege interfața după ordinea enumerării sau
metrică. Loopback, interfețele LAN inactive și tunelurile exclusiv IPv6
sunt excluse din selecția IPv4. Apelantul trebuie să oprească operația la
eroare. Detectarea nu execută Nmap și nu confirmă identitatea hotspot-ului;
scannerul trebuie conectat în prealabil la laboratorul dorit.

### Autorizarea persistentă a laboratorului

`validate_scan_request(..., confirm=True)` fără allowlist explicit citește
`lab/network.json`. Dacă fișierul lipsește sau este invalid, cererea este
refuzată; rețeaua curentă nu devine automat autorizată la scanare.

După verificarea manuală a conexiunii la laborator, `configure-lab` poate
propune subnetul detectat, dar confirmarea explicită este obligatorie:

```sh
python -m netcheck configure-lab
python -m netcheck configure-lab --confirm
```

Alternativ, configurați explicit CIDR-ul autorizat (valoarea de mai jos
descrie doar sesiunea documentată):

```python
from netcheck.scanner import configure_lab_network, validate_scan_request

configure_lab_network(["172.20.10.0/28"], confirm=True)
validated = validate_scan_request("172.20.10.3", confirm=True)
```

Configurarea salvează allowlist-ul și interfața, IPv4, prefixul, subnetul,
gateway-ul detectate; nu suprascrie o configurare existentă. Fișierul este
local și exclus din Git. Pentru alt laborator, eliminați deliberat fișierul
vechi și autorizați noua configurație. Parametrul `config_path` permite o
altă locație. Transmiterea unui `allowed_networks` explicit reprezintă o
autorizare pentru cererea respectivă, legată de rețeaua curentă.

Țintele și allowlist-ul trebuie să fie integral în intervalele RFC1918;
loopback, link-local, multicast, adresele rezervate și publice sunt refuzate.
Ținta validată și rețeaua asociată sunt imuabile, allowlist-ul este un tuple,
iar semnătura internă leagă toate valorile de validarea din procesul curent.
Înainte de lansare se reverifică integritatea, politica și rețeaua. Orice
schimbare a configurației salvate a rețelei, inclusiv IP-ul local, cere
reautorizare. Obiectul validat nu se reutilizează între procese.

Aceste verificări nu autentifică hotspot-ul: două rețele cu exact aceiași
parametri IP nu pot fi distinse astfel. Nici modificările de rutare după
ultima verificare nu pot fi prevenite printr-o simplă verificare în Python.
Codul executat în același proces și fișierul de autorizare sunt de încredere.
CLI și API sunt conectate la aceeași validare prin `netcheck.service.scan`.
**Taskul 4 este implementat și verificat prin teste automate cu scanări
simulate.** Instrucțiunile CLI/API și checklist-ul sunt în [README](../README.md).

### Contextul celorlalte laptopuri

Laptop care găzduiește HTTP: **Laptop 2 (Windows)**.
Gateway raportat: **172.20.10.1**.
Aceste adrese descriu sesiunea comunicată și trebuie reverificate la reluare.
Asocierea gazdei HTTP cu Windows provine de la echipă, nu din XML.

Pe macOS, identificați interfața Wi-Fi cu `networksetup -listallhardwareports`,
apoi folosiți `ifconfig <interfata>` pentru IP și netmask și
`route -n get default` pentru ruta implicită. Pe Windows, folosiți
`ipconfig /all` pentru adaptorul Wi-Fi și `route print -4` pentru rute.
Înregistrați masca exact cum este afișată dacă prefixul nu a fost determinat.
Verificați și SSID-ul în setările Wi-Fi; nu confundați adaptorul hotspot-ului
cu un adaptor VPN sau cu o conexiune Ethernet.

Verificări raportate de echipă pentru sesiunea curentă:

- [x] Cele trei laptopuri folosesc hotspot-ul `RSH-REXA`.
- [x] Parola este puternică, generată automat în Passwords; parola nu este
  inclusă în documentație.
- [x] Scannerul este deconectat de la rețeaua locației.
- [x] Scannerul nu are VPN.
- [x] Scannerul, gazda HTTP, IP-urile și gateway-ul sunt comunicate.
- [ ] Interfețele și măștile/prefixele celor trei laptopuri sunt confirmate.

Ping-ul a fost confirmat anterior de echipă, dar momentul și perechile exacte
nu au fost furnizate. Pentru o sesiune nouă, repetați către IP-urile curente:
`ping -c 4 <IP>` pe macOS și `ping -n 4 <IP>` pe Windows.

## Reproducerea serviciului HTTP

Acești pași definesc o configurație reproductibilă pentru următoarea sesiune;
nu pretind că reconstruiesc comenzile originale, care nu apar în XML.
Gazda HTTP aleasă este Laptop 2 (Windows); scannerul este Laptop 1 (macOS).
Sunt necesare Python 3 pe Windows și Nmap pe scanner. Verificați cu
`py -3 --version` în PowerShell, respectiv `nmap --version` pe Mac.
Dacă launcher-ul `py` nu este disponibil, folosiți `python` în loc de `py -3`
după ce confirmați că `python --version` indică Python 3.

Pe Laptop 2, în **PowerShell**, creați un folder temporar dedicat și pagina
statică, apoi introduceți IP-ul curent al adaptorului conectat la hotspot
(`172.20.10.3` în sesiunea raportată):

```powershell
$LabHttpDir = Join-Path $env:TEMP ("smarthack-http-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $LabHttpDir | Out-Null
@'
<!doctype html>
<html lang="ro">
<head><meta charset="utf-8"><title>Admin Login</title></head>
<body><h1>Admin Login</h1><p>Pagina statica pentru laborator.</p></body>
</html>
'@ | Set-Content -Path (Join-Path $LabHttpDir 'index.html') -Encoding UTF8
Write-Output "Folder HTTP: $LabHttpDir"
$LabHttpIp = Read-Host 'IP-ul curent al laptopului Windows pe hotspot'
py -3 -m http.server 8080 --bind $LabHttpIp --directory $LabHttpDir
```

Serverul rămâne în prim-plan. Dacă firewall-ul cere acces, permiteți serviciul
pentru testul autorizat și consemnați schimbarea; nu dezactivați global firewall-ul.
De pe scanner, deschideți `http://<IP-curent-gazda>:8080/` și verificați titlul
`Admin Login`. Pagina este statică și nu implementează autentificare.

Pe Laptop 1 (macOS), în **zsh**, din rădăcina repository-ului, salvați o scanare
nouă într-un folder unic (nu peste captura preliminară):

```sh
read -r 'LAB_TARGET_IP?IP-ul curent al gazdei HTTP pe hotspot: '
LAB_RUN_DIR="$(mktemp -d lab/preliminary/run.XXXXXX)"
nmap -Pn -sV --script http-title -p 8080 -oX "$LAB_RUN_DIR/http_test.xml" "$LAB_TARGET_IP"
```

Pentru oprire, apăsați **Ctrl+C** în terminalul serverului. Verificați că pagina
nu mai este accesibilă printr-o cerere nouă. Folderul temporar poate fi păstrat
pentru inspecție; nu conține date necesare capturii originale. Versiunile
Python și antetele pot diferi de testul inițial: consemnați versiunile efective.

## Predare către Georgiana

Pachet pregătit: [`preliminary/http_test.xml`](preliminary/http_test.xml) și
acest README. Fișierele nu au fost trimise Georgianei de către asistent.
Canalul (de exemplu e-mail) și adresa destinatarului nu au fost stabilite.

Așteptările furnizate pentru această captură sunt:

| Constatare | Port așteptat |
| --- | --- |
| `HTTP_ADMIN_CLEARTEXT` | `8080` |
| `UNKNOWN_DEVICE` | gol (nu `0`) |

Scor așteptat: **85**. Aceste valori sunt criterii de validare comunicate de
echipă, nu rezultate calculate. La verificarea repository-ului,
`netcheck/catalog.json` este gol (`{}`), iar modulele `rules.py` și `scoring.py`
conțin doar docstring-uri. Așteptările nu pot fi încă verificate prin motorul
local și nici confirmate dintr-un catalog implementat. Georgiana trebuie să
compare rezultatul motorului cu aceste așteptări după implementare.
