# Smarthack / Netcheck

Prototip pentru tema **Secure Networks, Simply Explained**: scanarea unei
rețele proprii, explicarea riscurilor și verificarea remedierilor.

În prezent sunt implementate detectarea rețelei, autorizarea laboratorului,
scannerul și accesul prin CLI/API local. **Analiza offline, findings, scorul,
istoricul și interfața pentru utilizator nu sunt încă implementate.**
Starea pe cerințe și pașii rămași sunt în [starea proiectului](docs/project-status.md).

## Instalare

Necesită Python 3.10+. Din rădăcina repository-ului, pe macOS/Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

Pe Windows, în PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

`requirements-dev.txt` include dependențele aplicației și testele. Nmap se
instalează separat, cu baza sa `nmap-services`; nu este necesar pentru
simpla detectare a rețelei. Pentru Docker/HTTP de laborator, urmați
[instrucțiunile serviciilor](lab/services/README.md).

Comenzile de mai jos folosesc `python` din mediul virtual activat
(`source .venv/bin/activate` pe macOS/Linux). Pe Windows puteți înlocui
`python` cu `.\.venv\Scripts\python.exe`, fără activarea mediului.

## Detectare și autorizare

Conectați scannerul numai la laboratorul echipei, apoi:

```sh
python -m netcheck network
python -m netcheck configure-lab --allow 172.20.10.0/28 --confirm
```

Înlocuiți exemplul cu subnetul real, după verificarea faptului că aveți
permisiunea de scanare. Detectarea IP nu dovedește proprietatea rețelei.
`configure-lab` salvează allowlist-ul și configurația rețelei în
`lab/network.json`, exclus din Git, și refuză suprascrierea. Pentru o nouă
configurație, eliminați deliberat fișierul vechi și reautorizați laboratorul.
Opțiunea globală `--config CALE` se pune înaintea subcomenzii.

Scanarea acceptă numai ținte IPv4/CIDR din intervalele private RFC1918,
cu maximum 256 de adrese și incluse integral în allowlist și LAN-ul autorizat.
Confirmarea este obligatorie. Schimbarea configurației rețelei provoacă refuz,
inclusiv schimbarea IP-ului scannerului prin DHCP. Configurația curentă nu
este autorizată automat. CLI și API folosesc aceeași funcție de serviciu.

## Scanare și API local

```sh
python -m netcheck scan 172.20.10.3 --confirm
python -m netcheck serve
```

**Execuția live necesită încă pregătirea și verificarea privilegiilor Nmap
pe laptopul scanner.** Comanda folosește TCP SYN și UDP, care necesită
privilegii/driver corespunzătoare. Nu rulați întregul CLI, analizor sau server
web cu `sudo` pentru a ocoli acest lucru: privilegiile trebuie limitate la
pasul Nmap. Integrarea completă a acestui mecanism rămâne de făcut.

Scannerul selectează cel puțin top 1.000 TCP din baza locală `nmap-services`
(inclusiv egalitățile la frecvența de pe poziția 1.000), plus exact UDP
53, 123, 161, 1900 și 5353. Folosește identificarea serviciilor/versiunilor,
`http-title`, `-n` și `--max-rate 100`. Scripturile au timeout de 30 secunde;
procesul are timeout de 300 secunde. Rezultatul este verificat ca XML Nmap
complet, cu parsare sigură și limită de 10 MB. Un timeout este un eșec,
**nu o dovadă că cerința de scanare a unui /24 în sub cinci minute este atinsă**.

`scan` returnează JSON și scrie XML într-un fișier unic din `scans/`
(sau `--output-dir CALE`). XML-urile brute pot conține date despre dispozitive;
folderul este local și exclus din Git. Mascarea datelor în produsul final
rămâne parte din implementarea analizorului/UI. Rezultatul scannerului nu
conține încă findings sau scor.

O singură scanare poate rula simultan prin serviciu în același checkout,
inclusiv între procese CLI/API. Blocarea folosește `.netcheck-scan.lock`,
exclus din Git; fișierul poate rămâne pe disc după oprire, dar blocarea este
eliberată de sistem. Nu ștergeți fișierul în timpul execuției.

`serve` ascultă exclusiv pe `127.0.0.1:8000`. API-ul este destinat utilizării
locale, nu expunerii în rețea. Documentația interactivă este la `/docs`.
Aceasta nu înlocuiește interfața pentru utilizator cerută de hackathon.

- `GET /api/network`: detectare fără scanare.
- `POST /api/scan`: `{"target":"172.20.10.3","confirm":true}`.
- `confirm` acceptă numai booleanul `true`, nu `"true"` sau `1`.
- Cererile nu pot modifica allowlist-ul, configurația, argumentele Nmap sau
  calea de ieșire.
- HTTP: 200 succes; 403 refuz de autorizare; 409 rețea indisponibilă/ambiguă
  sau scanare deja în curs; 422 cerere invalidă; 500 eroare locală de fișier;
  502 eșec al scanării, inclusiv Nmap absent sau XML invalid.
- CLI: 0 succes; 1 eroare de execuție/fișier; 2 refuz, rețea indisponibilă,
  scanare deja în curs sau argumente invalide.

## Verificare

```sh
python -m pytest -q
```

Testele normale simulează Nmap, fără trafic de scanare. Pentru citirea reală
a configurației locale, tot fără scanare, setați `NETCHECK_NATIVE_TEST=1`.
Pe macOS/Linux:

```sh
NETCHECK_NATIVE_TEST=1 python -m pytest tests/test_network_native.py -q
```

Detectarea a fost verificată pe Mac-ul laboratorului. Windows/Linux au
backend-uri și teste simulate; workflow-ul CI este configurat, dar rezultatele
sale nu sunt încă confirmate în această documentație. Verificați nativ fiecare
platformă înainte de demonstrație. Detalii: [detectarea rețelei](docs/network-detection.md).

Documentația laboratorului și captura HTTP preliminară sunt în
[lab/README.md](lab/README.md). Pentru continuarea lucrului, consultați
[cerințele încă deschise](docs/project-status.md).
