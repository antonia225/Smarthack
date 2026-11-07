# Starea proiectului față de brief

Evaluare la 7 noiembrie 2026. Acest fișier separă implementarea existentă de
validarea reală și de cerințele încă neimplementate. Testele automate cu
procese simulate nu certifică o scanare a laboratorului. În această revizie
nu s-au pornit scanări live sau servicii de laborator.

## Ce este disponibil

În această revizie au fost reparate prin cod și teste: wrapperul macOS
compară directoare rezolvate, acceptă numai ținte RFC1918 și primește lista
TCP generată din `nmap-services`; `scan --confirm` poate folosi subnetul
autorizat din configurație; verificatorul XML are logică unificată. Privilegiile
macOS, scanarea reală, BEFORE/AFTER și rezultatele gitleaks rămân
**NEVERIFICATE live**.

| Componentă | Implementare și dovadă | Ce mai trebuie verificat |
| --- | --- | --- |
| Task 1: laborator documentat | Hotspot, roluri și captură HTTP reală păstrată; instrucțiuni de reproducere | Completați inventarul interfețelor/prefixelor țintelor și confirmați reproducerea pe configurația curentă |
| Task 2: servicii de laborator | Compose PostgreSQL/MQTT, simulatoare FTP/Telnet și HTTP separat; verificator după catalog | Scanare între laptopuri cu cinci tipuri distincte; probele anterioare au avut identificări HTTP/MQTT/FTP necorespunzătoare |
| Task 3: detectarea rețelei | IP, interfață, prefix, subnet și gateway; verificare nativă pe Mac; teste simulate macOS/Windows/Linux | Verificare nativă reușită pe Windows/Linux înainte de folosirea lor la prezentare; rezultatele workflow-ului CI nu sunt încă observate |
| Task 4: guardrail | Confirmare, allowlist persistent RFC1918, obiect validat imuabil și semnat, reverificarea rețelei, CLI/API comune | Repetarea refuzurilor în mediul de prezentare; configurația IP nu autentifică proprietarul hotspot-ului |
| Executarea scanării | Selecție TCP/UDP, limită de rată, timeout, verificare XML sigură, durată și erori, blocare între fire/procese | Privilegii limitate la procesul Nmap, scanare reală completă și măsurarea performanței |

Pot fi folosite numai un Mac și un Windows: Mac-ul scanează, Windows găzduiește
HTTP și containerele. Brief-ul cere minimum trei dispozitive **sau servicii**,
nu trei laptopuri țintă. Instrucțiuni: [servicii](../lab/services/README.md).

Nu considerați Taskul 2 finalizat până când XML-ul real al rețelei autorizate
nu justifică minimum cinci tipuri de findings conform numelor serviciilor din
catalog. Un port deschis, o scanare pe loopback sau o excepție introdusă în
verificator nu sunt suficiente. Nu modificați XML-urile pentru a obține
rezultatul așteptat.

## Cerințe obligatorii încă deschise

| Cerință din brief | Stare și rezultat necesar |
| --- | --- |
| FR-01 detectare | Implementată; suport nativ confirmat pe macOS |
| FR-02 domeniu autorizat | Implementat și testat cu simulări; demonstrați refuzul IP-urilor publice, rețelei locației și lipsei confirmării |
| FR-03 dispozitive | `parser.py` este schelet; trebuie IP, MAC mascat, vendor, hostname și estimare de tip |
| FR-04 porturi/servicii | Selecția top 1.000 TCP din `nmap-services`, wrapperul macOS generat și execuția limitată sunt implementate și testate; scanarea reală și acoperirea necesită verificare |
| FR-05 analiză offline | Neimplementată; parser sigur, erori explicite, fără acces la rețea |
| FR-06 reguli | `rules.py` și catalogul sunt neimplementate; brief-ul are **15 coduri**, inclusiv `SSH_OPEN` (nu 14), numai pe porturi `open` și după numele serviciului |
| FR-07/08 explicații și remedieri | Catalogul este gol; maximum două propoziții și 1–5 pași concreți per finding, în RO/EN |
| FR-09 scor | `scoring.py` este schelet; `max(0, 100 - suma punctelor)` |
| FR-10 istoric | `history.py` este schelet; scanări locale, diferențe și evoluția scorului, plus ștergere completă |
| FR-11 UI | Fișierele web sunt schelet; trebuie scor, dispozitive, findings, pași și istoric; `/docs` nu este UI-ul cerut |
| FR-15 rezultate standard | Comanda `analyze` și exporturile pe folder nu există; produceți `findings.csv` și `scores.csv` |

Validation Set trebuie obținut și păstrat ca fixtures: opt fișiere XML,
**24 de rânduri de findings fără rânduri suplimentare**, cu scorurile
90, 40, 45, 25, 50, 60, 100 și ERROR. Fișierele expected existente nu
înlocuiesc setul oficial și un test de validare executabil. În prezent,
`tests/test_validation.py` este doar schelet.

Captura `lab/preliminary/http_test.xml` are așteptarea
`HTTP_ADMIN_CLEARTEXT` pe 8080 și `UNKNOWN_DEVICE` cu port gol, scor **85**.
Acesta este un rezultat calculat din brief pentru verificare, nu un rezultat
produs deja de motorul aplicației.

## Securitate, fiabilitate și utilizare

- **Privilegii (NFR-04):** implementat și testat fără execuție Nmap, dar
  **neverificat live**. Pe macOS,
  sudoers permite numai wrapperul root-owned, nu binarul Nmap; wrapperul
  validează ținta și calea XML și fixează comanda. Pe Windows se folosește
  Nmap ne-elevat cu Npcap încărcat, conform documentației oficiale Nmap.
  Nu rulați FastAPI, UI-ul sau analizorul cu `sudo`. Verificați manual pașii
  și `visudo -c` pe laptopurile respective înainte de demonstrație.
- **Intrări ostile (NFR-03):** verificarea rezultatului scannerului are parsare
  XML sigură și limită de 10 MB. Parserul offline și importul viitor trebuie
  să aplice aceleași protecții; UI-ul va trata bannerele ca text, fără HTML.
- **Date locale (NFR-02):** istoricul și hostname-urile rămân locale; toate
  ieșirile produsului trebuie să mascheze MAC-urile. XML-ul brut de scanare
  poate conține date complete: revizuiți capturile înainte de distribuire.
- **Secrete (NFR-01):** configurația locală și parola temporară DB sunt în
  afara Git, iar `.env.example` documentează explicit că aplicația nu citește
  variabile de mediu. Au   fost adăugate configurația, jobul CI și scripturile gitleaks pentru working
  tree și istoric. **Configurat, neobservat încă**: rularea live gitleaks trebuie
  făcută manual și în CI.
- **Determinism (NFR-05):** viitorul motor va produce identic findings,
  severități și scoruri; nu folosiți LLM pentru aceste decizii.
- **Performanță (NFR-07):** măsurați analiza offline sub 30 s/fișier și scanarea
  unui /24 sub cinci minute. Timeout-ul de 300 s doar oprește o scanare lungă;
  nu demonstrează reușita sau acoperirea scanării în acel timp.
- **Limbă și accesibilitate (NFR-08/09):** toate textele produsului în RO/EN,
  minimum 16 px, tastatură, contrast AA, icon și etichetă pe lângă culoare.
  Mesajele și ajutorul CLI necesită încă revizie lingvistică completă.
- **Reproducibilitate (NFR-10):** `scripts/setup.py` creează `.venv`,
  instalează `requirements-dev.txt` și raportează lipsa Nmap; verificarea într-un
  mediu curat și instalarea separată a Nmap rămân de confirmat manual.

## Ce se livrează în continuare

1. Finalizați laboratorul cu cinci tipuri de findings și acces între laptopuri.
2. Finalizați parserul, cele 15 reguli, scorul și exporturile; verificați cele
   24 de rânduri oficiale înainte de îmbunătățiri vizuale sau AI.
3. Implementați istoricul și UI-ul; utilizatorul trebuie să identifice rapid
   dispozitivul cel mai riscant și primul pas de remediere.
4. Reparați minimum două findings reale, rescanați și păstrați BEFORE/AFTER,
   cu scor îmbunătățit și findings rezolvate afișate în istoric.
5. Pregătiți sumarul tehnic de o pagină și pitch-ul de 5–7 minute în engleză,
   cu minimum doi membri vorbind, plus formularele de participare semnate.
6. Pregătiți rezultatele Test Set, screenshot-ul UI și release-ul/tag-ul `final`,
   respectând ferestrele de predare din brief. După încărcarea rezultatelor,
   rerularea trebuie să reproducă exact rezultatele fără modificări de cod.
7. Repetați cele șapte verificări live: rerulare, utilizare UI, trei explicații,
   guardrail, XML stricat, istoric BEFORE/AFTER și verificarea secretelor.

Q&A cu AI și alertele sunt Should; raportul HTML/PDF este Could. Acestea pot
urma după Must-uri. Dacă se adaugă AI, explicațiile trebuie ancorate în
scanare și să aibă text local de rezervă.
