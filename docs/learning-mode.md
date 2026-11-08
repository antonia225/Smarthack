# Learning Mode — arhitectură și verificare

Learning Mode explică o scanare salvată. Parserul, regulile și scoringul produc
finding-urile, severitățile, tipurile estimate și scorul; răspunsul LLM nu este
scris în analiza salvată și nu poate porni o scanare sau aplica remedieri.

## Arhitectură

1. `scripts/build_knowledge.py` construiește corpusul Faza 2a din allowlistul
   `knowledge/sources.json`, numai cu stdlib. Descarcă o dată, reutilizează cache-ul
   sau documentele existente și scrie pasaje de 80–200 cuvinte `kb:<id>#n`,
   metadate cu revizie și `knowledge/index.json`. Resursele link-only
   sunt separate în `knowledge/resources.json`; vezi [NOTICE](NOTICE.md).
2. `netcheck/learn/retriever.py` caută lexical, cu BM25 determinist, în indexul
   pasajelor, titluri, coduri, keywords RO/EN și catalogul local bilingv.
   Normalizează diacriticele și majusculele; nu folosește embeddings.
3. `POST /api/ask` primește `scan_id`, `question`, `lang` (`ro`/`en`) și opțional
   `device_ip`; încarcă analiza din SQLite și construiește dovezile.
4. `netcheck/prompts/system_ro.md` sau `system_en.md`, dovezile, pasajele și
   întrebarea ajung în adaptorul `learn/agent.py`. Regulile sunt un mesaj system, iar contextul și întrebarea sunt un mesaj user.
5. Adaptorul trimite chat-completions către endpointul configurat numai dacă
   există atât cheia, cât și modelul; timeoutul de rețea este 8 secunde.
6. Validatorul verifică marcajele de citare față de ID-urile efectiv furnizate și compară anumite
   valori (IP, numere, URL, CVE, telefon) cu textul permis. La eroare sau
   respingere se întoarce fallback-ul local, cu `mode: fallback`; altfel `ai`.

## Ce face și ce NU face LLM-ul

LLM-ul reformulează explicații pe baza dovezilor și pasajelor. Instrucțiunile îi
cer să nu inventeze constatări sau remedieri. Nu calculează scorul, nu stabilește
porturi deschise ori severități și nu modifică istoricul. Aceste restricții de
arhitectură nu garantează că textul generat este corect: validatorul nu verifică
semantic afirmațiile. Recomandările necesită
verificare umană înainte de aplicare.

## Date pseudonimizate

Dovezile folosesc etichete numerotate de tip `Dispozitiv 1` / `Device 1`, dar includ IP-uri reale, tipul
estimat, porturile și numele serviciilor, coduri de finding, severități și scor.
MAC-urile, hostname-urile, bannerele brute și titlurile HTTP nu sunt incluse de
constructorul de dovezi. Acesta este un context pseudonimizat, nu anonim.
Întrebarea liberă este trimisă integral: nu introduce secrete sau identificatori
în ea. Pasajele locale sunt de asemenea trimise furnizorului configurat.
Marcarea datelor ca informații, nu instrucțiuni, reduce riscul de prompt injection,
fără să îl elimine. Nu există aici o politică de retenție impusă furnizorului.

## Configurare și fallback

Aplicația citește mediul procesului; **nu încarcă automat `.env`**. Din rădăcina
proiectului, cu mediul virtual activat:

```sh
# Mod local, fără apel extern:
unset NETCHECK_LLM_API_KEY NETCHECK_LLM_MODEL NETCHECK_LLM_API_URL
python -m netcheck serve
```

Pentru un furnizor aprobat, exportă `NETCHECK_LLM_API_KEY`, `NETCHECK_LLM_MODEL`
și opțional `NETCHECK_LLM_API_URL` înainte de pornire (vezi `.env.example`).
Cheia nu se introduce în UI și nu se salvează în Git.

Fără cheie/model, la eroare de rețea, timeout sau răspuns respins, asistentul
folosește o explicație scurtă din catalog, numai în limba cerută. Nu copiază
pasajele externe în limba lor originală. Dacă nu are informații potrivite,
răspunde „Nu am informații despre asta în documentația mea.” (sau în engleză).
Citările sunt verificate intern și eliminate înainte de salvare și afișare;
`sources` este gol. Instrucțiunile cer maximum 3 propoziții, 60 de cuvinte și
20 de cuvinte pe propoziție. Validatorul respinge lungimea excesivă și indicii
uzuale de limbă greșită sau amestecată; nu este un detector lingvistic complet.

## Recomandări și agent de remediere

Fiecare recomandare are două butoane: „Arată-mi pașii” afișează pașii locali,
iar „Repară cu agentul” trimite o cerere explicită la `POST /api/agent/remediate`.
Backendul verifică dacă problema aparține scanării și cere `confirm: true`.
Nu rulează comenzi generate de LLM.

În proiect nu există un serviciu de remediere automată. Scripturile din
`scripts/macos` și `scripts/windows` sunt doar pentru laborator și nu sunt
executate de acest endpoint. Conexiunea nouă cere `NETCHECK_REMEDIATION_URL`
și, opțional, `NETCHECK_REMEDIATION_API_KEY` în mediul serverului. Agentul primește
JSON cu `scan_id`, `device_ip`, `finding_code`, `port`, `lang`; răspunde cu
`{"status":"ok"}` la final sau `{"status":"accepted"}` dacă a pus cererea în coadă.
Fără configurare, API-ul returnează 503 și UI-ul oferă pașii manuali.
Nu a fost verificată execuția unui agent extern real.
## Răspunsuri locale din scanare

Fără furnizor configurat, `brief_answer` păstrează răspunsurile despre scor,
severitate, dispozitivul cel mai expus, primul pas și porturi, pe baza analizei
salvate. Nu recalculează finding-uri sau scoruri. Răspunsul public este scurt,
în limba cerută, fără prefix de sursă și cu `sources: []`.

Implementarea detaliată din `answer` și utilitarele pentru curățarea pasajelor
rămân disponibile intern, dar nu sunt afișate de endpointul de conversație.
Întrebările despre un protocol explicit au prioritate față de dispozitivul
selectat. Pentru instrucțiuni specifice meniurilor, asistentul cere marca și
modelul. Filtrul acceptă întrebări complete despre scanare și continuări neutre;
un cuvânt generic precum „cum” nu autorizează o întrebare despre Paris.

Catalogul funcționează fără corpus descărcat. Dacă serverul local nu răspunde,
UI-ul afișează un mesaj scurt de indisponibilitate.

## Limitări

Corpusul nu se construiește la pornire. Builderul păstrează numai textul extras
din sursele declarate și marchează explicit documentele indisponibile; nu
completează text lipsă. Pasajele rămân în limba originală, inclusiv în căutări RO,
care folosesc keywords românești; în promptul AI ajung ca atare, iar fallback-ul
afișează numai pasaje în limba cerută. Catalogul este afișat în limba cerută.
Recunoașterea întrebărilor în fallback este pe expresii fixe: formulările
necunoscute ajung la căutarea locală, a cărei relevanță rămâne limitată.
Retrieverul verifică ID-urile și URL-urile din allowlist; metadatele de revizie
și atribuire sunt în [NOTICE](NOTICE.md). Un hash HTTP nu garantează o revizie
editorială. Validatorul nu garantează corectitudinea semantică a răspunsurilor.
Detaliile corpusului, comenzile cache/offline și rezultatul Fazei 2a sunt în
[knowledge/README.md](../knowledge/README.md).

## Verificare — 8 noiembrie 2026

`.venv/bin/python -m pytest -q`: **262 passed, 1 skipped, 1 warning**
(3,56 s; după implementarea corpusului Faza 2a). Warning: deprecare Starlette TestClient/httpx. `git diff --check`
a trecut. Nicio scanare reală nu a fost pornită.

Inspecția de cod nu echivalează cu o probă manuală în browser. Browserul de
verificare nu a fost disponibil (`browser access host is unavailable`).

| Cerință | Rezultat și limite |
| --- | --- |
| Numai tastatură | Nedemonstrat manual. Există skip-link, butoane native, Enter/Space pe noduri și focus programatic în panou; fluxul complet și vizibilitatea focusului trebuie probate. |
| Contrast AA | Culorile principale au fost calculate: text 5,59–6,75:1; bordură pe fundal 3,51:1; focus pe alb 5,39:1. Bordurile și hover-ul primar au fost corectate. Conformitatea întregii pagini randate rămâne nedemonstrată. |
| RO/EN complet | Problemele identificate sunt corectate: etichete localizate, explicații bilingve selectate la randare, dovezi și antete de prompt localizate, corpus căutat prin keywords bilingve, fără traducerea textelor sursă. Mesajele anterioare sunt eliminate la schimbarea limbii. Proba vizuală completă rămâne de făcut. |
| Fără cheie | Acoperit de test API offline; proba manuală UI rămâne de făcut. |
| Fără internet | Eroarea de rețea este simulată prin adaptorul real, iar timeoutul în API; deconectarea reală cu furnizor configurat nu este demonstrată. |
| Esc în panou | Handlerul implementează chat → detalii → listă și focus în inspector; verificat cu DOM stub și taste simulate, nedemonstrat manual. |

Mesajul despre AI explică acum furnizorul opțional și datele trimise. Panoul are
un titlu ARIA valid în fiecare stare; câmpul chat și linkurile au focus explicit.
Au fost conectate și lista alternativă de dispozitive, butoanele de import și
selectorii comparației. Răspunsurile întârziate nu mai suprascriu conversația
altui dispozitiv sau altei limbi. Testul `node tests/web_learning.test.js`
verifică traducerile dinamice, titlurile panoului, focusul și tranzițiile Esc
cu DOM stub; nu înlocuiește verificarea în browser.

## Pași exacți pentru demonstrație

1. Activează `.venv`: `source .venv/bin/activate` și rulează
   `python -m pytest -q`. Testele nu pornesc scanări reale.
2. Cu internet: `python scripts/build_knowledge.py`. Cere exit 0, verifică
   fiecare fișier generat și metadatele; un exit 1 înseamnă corpus parțial.
   Corpusul Faza 2a a fost construit live: **34/34 documente, 642 pasaje, exit 0**.
   Reconstrucția `--offline` a trecut. Relevanța și secțiunile auxiliare rămân
   inspectabile în fișierele generate.
3. Pornește modul fără cheie folosind comenzile de mai sus. Deschide
   `http://127.0.0.1:8000`, importă `tests/validation/V6a_before.xml` prin Import.
4. Folosește doar Tab/Shift+Tab, Enter, Space și săgețile selectului: verifică
   skip-link, navigare Acasă/Istoric/Import, selector, hartă, constatări,
   detalii, chat, formular și dialog (anulează ștergerea). Notează orice focus
   pierdut sau control inaccesibil. În chat, Esc trebuie să revină la detalii;
   încă un Esc la lista de constatări, cu focus vizibil în panou.
5. În RO și apoi EN, verifică toate ecranele, răspunsul fără surse. Reîncarcă
   pagina și testează și schimbarea dinamică; explicațiile trebuie să treacă
   imediat în limba selectată. Nu declara proba vizuală reușită înainte de rulare.
6. Măsoară în instrumentele de accesibilitate ale browserului contrastul textului
   (minimum 4,5:1, sau 3:1 pentru text mare), controalelor și focusului (3:1),
   inclusiv hover, selectat, severități și erori. Salvează valori/capturi.
7. Trimite o întrebare fără cheie: cere `mode: fallback`, text scurt în limba aleasă și `sources: []`
   în răspunsul `/api/ask` din Network. Oprește internetul, păstrând serverul
   pornit, și repetă; pagina și catalogul trebuie să funcționeze local.
8. Pentru proba live, repornește serverul cu cheia/modelul furnizorului aprobat
   exportate. Folosește numai fixture-ul, fără date sensibile în întrebare.
   Cere `mode: ai`; fallback-ul singur nu dovedește un apel LLM reușit. Apoi
   deconectează internetul și repetă pentru fallback la eroare. Notează modelul,
   data, răspunsul și modul, fără cheie. Reactivează internetul și elimină cheia
   din mediu după probă. LLM-ul nu a fost testat live în această verificare.
