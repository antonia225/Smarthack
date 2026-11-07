# Task 2: cinci servicii accesibile prin hotspot

Scop: HTTP_ADMIN_CLEARTEXT, DB_EXPOSED, MQTT_EXPOSED, TELNET_OPEN,
FTP_CLEARTEXT in XML real. Trei sau mai multe servicii satisfac numarul
minim de tinte/servicii; nu sunt necesare trei gazde distincte.

## Fisiere necesare

- compose.yaml: PostgreSQL, MQTT si doua simulatoare.
- mosquitto.conf: broker fara date reale sau persistenta.
- simulators.py: FTP si Telnet fara shell, login functional sau fisiere.
- check_xml.py: verifica cele cinci reguli dupa service name, nu dupa port.


## 1. Pregatirea

Toate laptopurile trebuie sa fie pe hotspot-ul echipei. Scannerul nu trebuie
conectat la reteaua locatiei. Identificati IP-urile curente:
Windows: `ipconfig`; Mac: `networksetup -listallhardwareports`, apoi
`ifconfig <interfata>`. Nu reutilizati automat IP-urile din capturile vechi.

Varianta cu doua laptopuri: Mac = scanner; Windows = Docker si HTTP.
Prerechizite: Docker Desktop pornit pe Windows, in modul Linux containers,
Python 3 pe Windows, Nmap si Python 3 pe Mac. Copiati folderul lab/services
pe Windows. Optional, Docker poate rula pe un al doilea Mac.

## 2. Gazda Docker: pornirea serviciilor

Pe Windows, din folderul services, in PowerShell:

```powershell
$env:LAB_BIND_IP = Read-Host 'IP-ul Windows pe hotspot'
$env:LAB_DB_PASSWORD = [guid]::NewGuid().ToString('N')
docker info
docker compose config --quiet
docker compose up -d
docker compose ps
docker compose logs --tail 30
```

Alternativ, pe un al doilea Mac, din folderul services, in zsh:

```zsh
read -r 'LAB_BIND_IP?IP-ul Mac-ului Docker pe hotspot: '
export LAB_BIND_IP
export LAB_DB_PASSWORD="$(openssl rand -hex 24)"
docker info
docker compose config --quiet
docker compose up -d
docker compose ps
docker compose logs --tail 30
```

Toate cele trei containere trebuie sa fie pornite. Parola DB este generata
local in mediul terminalului, nu salvata in repo. Datele sunt efemere; nu
folositi date personale. Pastrati terminalul pentru oprirea containerelor.
Porturile sunt publicate doar pe IP-ul introdus.

## 3. Windows: pornirea HTTP

In PowerShell:

```powershell
$LabHttpDir = Join-Path $env:TEMP ('smarthack-http-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $LabHttpDir | Out-Null
'<html><head><title>Admin Login</title></head><body>Laborator</body></html>' | Set-Content (Join-Path $LabHttpDir 'index.html') -Encoding UTF8
$LabHttpIp = Read-Host 'IP-ul Windows pe hotspot'
py -3 -m http.server 8080 --bind $LabHttpIp --directory $LabHttpDir
```

Lasati terminalul deschis. Daca firewall-ul blocheaza accesul, permiteti doar
scannerul si portul necesar; nu dezactivati firewall-ul global.

## 4. Mac 1: scanare din reteaua laboratorului

Din radacina repository-ului, in zsh:

```zsh
read -r 'LAB_HTTP_IP?IP-ul Windows pe hotspot: '
read -r 'LAB_DOCKER_IP?IP-ul Mac-ului Docker pe hotspot: '
mkdir -p lab/before
LAB_RUN_DIR="$(mktemp -d lab/before/services.XXXXXX)"
nmap -n -Pn -sT -sV --version-all --max-rate 100 --script http-title -p 8080 -oX "$LAB_RUN_DIR/http.xml" "$LAB_HTTP_IP"
nmap -n -Pn -sT -sV --version-all --max-rate 100 -p 21,23,1883,5432 -oX "$LAB_RUN_DIR/docker.xml" "$LAB_DOCKER_IP"
python3 lab/services/check_xml.py "$LAB_RUN_DIR/http.xml" "$LAB_RUN_DIR/docker.xml"
```

Daca Docker si HTTP ruleaza pe acelasi Windows, introduceti acelasi IP la
ambele intrebari.

Acestea sunt probe punctuale pentru Task 2, nu scannerul complet TCP/UDP.
Nu folositi 127.0.0.1: este necesara dovada accesului intre laptopuri.

## 5. Criteriul de finalizare

Verificatorul trebuie sa raporteze OK. Fiecare serviciu trebuie sa fie open,
cu numele oficial: http (fara SSL, cu titlul Admin Login), postgresql, mqtt,
telnet, ftp. Verificatorul nu calculeaza scorul aplicatiei.

Daca apare NECONFIRMAT, taskul ramane deschis. Pastrati XML-ul si verificati:
- filtered/closed: IP actual, serviciu pornit, publicare port si firewall;
- nume diferit: identificarea nmap trebuie rezolvata prin configurarea sau
  inlocuirea serviciului/simulatorului si o scanare noua. Nu editati XML-ul
  si nu adaugati exceptii la regulile oficiale pentru a forta rezultatul.

In probele locale anterioare au aparut http-proxy, mosquitto version 2.1.2
si nagios-nsca in locul numelor necesare. Configuratia actuala nu garanteaza
identificarea celor cinci servicii; scanarea prin hotspot este urmatorul
pas de verificare, nu o remediere garantata a acestor nume.

## 6. Oprire

Windows: Ctrl+C in terminalul HTTP.
Gazda Docker, din folderul services si terminalul in care ati setat
LAB_BIND_IP si LAB_DB_PASSWORD:

```zsh
docker compose down
```

Eliminati regulile temporare de firewall create pentru laborator. Daca
continuati imediat cu BEFORE/AFTER, documentati separat cele doua remedieri
si rescannati; oprirea tuturor serviciilor nu tine locul demonstratiei.
