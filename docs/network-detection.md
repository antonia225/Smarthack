# Detectarea rețelei scannerului

Implementarea include **macOS, Windows și Linux**. Platforma demonstrată live
este macOS. Backend-urile Windows și Linux sunt verificate cu teste automate
pe date simulate; verificarea nativă pe laptopuri Windows/Linux rămâne necesară
înainte de a le folosi la prezentare. Alte sisteme produc `NetworkDetectionError`.

Cerințe:

- macOS: `ifconfig` și `netstat`, disponibile în sistem.
- Windows: Windows PowerShell (`powershell.exe`) și modulele `NetAdapter` /
  `NetTCPIP` cu `Get-NetAdapter`, `Get-NetIPAddress`, `Get-NetRoute`.
  Datele sunt citite din ActiveStore și serializate JSON în UTF-8; numele
  interfețelor pot conține spații sau diacritice.
- Linux: `iproute2` cu suport JSON (`ip -j`) și sysfs montat la `/sys`.
  Adaptoarele fizice sunt identificate prin `/sys/class/net/<nume>/device`.
  Rutarea trebuie să folosească regulile standard local/main/default;
  policy routing și rutele multipath produc o eroare explicită.

Lipsa comenzilor, erorile de execuție, timeout-urile și datele invalide produc
`NetworkDetectionError`, fără fallback la un subnet presupus.

```python
from netcheck.scanner import detect_network, NetworkDetectionError

try:
    network = detect_network()
except NetworkDetectionError as error:
    raise SystemExit(str(error))
print(network)
```

Rezultatul `NetworkInfo` conține `interface`, `ip` (IPv4), `prefix_length`
(număr întreg), `subnet` (rețeaua în format CIDR) și `gateway` (IPv4).
Proprietatea `cidr` este un alias pentru `subnet`, păstrat pentru validarea existentă.

Funcția citește local configurația adaptoarelor, adreselor și rutelor:
`ifconfig`/`netstat` pe macOS, cmdlet-uri PowerShell pe Windows, respectiv
`ip -j -4 address`, `route show table all` și `rule show` pe Linux.
Nu execută probe de rețea sau scanări și nu solicită elevare de privilegii.
Subnetul este calculat din IPv4 și masca/prefixul raportat pentru acea adresă,
fără presupuneri despre hotspotul iPhone. Comenzile au timeout de 10 secunde.

Pentru demonstrație, conectați laptopul la laborator prin Wi-Fi sau Ethernet
(pe macOS, o interfață `enN`), cu o singură adresă IPv4 utilizabilă și un singur
gateway implicit în subnet. Deconectați celelalte conexiuni IPv4 și VPN-urile.
Loopback, adresele link-local și interfețele fizice inactive sunt excluse.
Interfețele virtuale/tunelurile IPv4 active, rutele IPv4 pe alte interfețe,
aliasurile IPv4 multiple, conexiunile multiple și gateway-urile absente sau
inconsistente produc o eroare explicită. Interfețele `utun` doar cu IPv6 nu
împiedică detectarea IPv4. Politica este conservatoare: și adaptoarele virtuale
legitime cu IPv4 pot necesita deconectare.

Detectarea identifică LAN-ul unic, nu poate autentifica faptul că acesta este
laboratorul sau că routerul este un iPhone. Laptopul trebuie conectat la
hotspotul laboratorului înainte de demonstrație. Apelantul trebuie să oprească
fluxul la `NetworkDetectionError`; funcția nu pornește scanări.

Verificare pe laptopul de prezentare, 7 noiembrie 2026:

```text
interface: en0
ip: 172.20.10.2
prefix_length: 28
subnet: 172.20.10.0/28
gateway: 172.20.10.1
```

Aceste valori au fost citite din configurația live și sunt doar rezultatul
verificării, nu constante în implementare. Repetați exemplul Python după
reconectare; DHCP poate schimba adresa sau masca.

Verificare înainte de demonstrație pe fiecare platformă:

1. Conectați doar adaptorul laboratorului și rulați exemplul Python de mai sus.
2. Comparați toate cele cinci câmpuri cu configurația nativă: `ipconfig /all`
   și `route print -4` pe Windows; `ip -4 addr` și `ip -4 route` pe Linux.
3. Deconectați LAN-ul: detectarea trebuie să eșueze explicit.
4. Reconectați LAN-ul și activați un VPN IPv4 sau un al doilea adaptor IPv4:
   detectarea trebuie să eșueze fără să aleagă arbitrar o rețea.

Instalati dependentele de dezvoltare cu `python -m pip install -r requirements-dev.txt`.
Testele automate pot fi rulate cu `python -m pytest -q`. Acestea verifică
prefixe reale, conexiuni absente/multiple, VPN-uri, gateway-uri invalide,
policy routing, date corupte și eșecuri ale comenzilor. Ele nu certifică
configurația driverelor sau disponibilitatea comenzilor pe alt laptop.
