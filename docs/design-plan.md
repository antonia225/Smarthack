# Plan de design: interfața web NetCheck

Mod skill: *Design improvement* (`.design-rules/SKILL.md`). Platformă: aplicație web desktop-first
servită local (FastAPI, HTML/CSS/JS fără biblioteci), care trebuie să funcționeze și îngust (<900 px).
Citările sunt din `.design-rules/references/hig/`; ce nu are sursă e marcat **[judecată]**.
Fișiere deschise efectiv: `design-principles`, `sidebars`, `toolbars`, `buttons`, `segmented-controls`,
`lists-and-tables`, `sheets`, `popovers`, `color`, `dark-mode`, `typography`, `materials`, `layout`,
`charts`, `accessibility`, `motion`, `progress-indicators`, `generative-ai`, plus `references/cross-platform.md`.

## 0. Limite ale acestui plan
- **Schița nu a fost văzută.** Nu există nicio imagine în proiect sau în conversație. Layout-ul de mai jos
  urmează *doar* textul tău (sidebar 240 px, grid `minmax(0,1fr) 360px`, bandă jos). Proporțiile fine,
  poziția exactă a elementelor și orice detaliu vizual din schiță nu sunt verificate.
- Web, nu app Apple: din `SKILL.md › Scope and limits`, primesc principiile și fundamentele
  (accesibilitate, culoare, tipografie, layout, writing), nu convențiile de platformă. Vocabularul
  e tradus conform `cross-platform.md › Vocabulary` (sidebar → sidebar + content pane; sheet → dialog;
  Liquid Glass → `backdrop-filter`; SF Symbols → set de icoane `<symbol>`).
- Brief-ul bate HIG (cerința ta, regula 4). Conflictele sunt listate la §8.

## 1. Teza designului
- **Treaba ecranului Acasă:** un nepot sau un jurat află în sub 30 s *care dispozitiv e cel mai periculos și ce
  face primul*. (`design-principles.md › Purpose`: „What is this screen for, and does the design serve it?”)
- **Elementul distinctiv (unul singur): „Rețeta”**, adică rândul prioritar din banda Vulnerabilități:
  „Cel mai periculos” + „Primul pas”, un singur pas, într-un bloc cu filet lateral în culoarea severității
  *și* iconiță *și* text. Justificare de produs: un control medical al rețelei pentru un bunic se termină cu
  *o* indicație, nu cu un raport. Tot restul rămâne liniștit, de sistem.
  Sursa principiului: `design-principles.md › Simplicity`: „Include just what’s necessary… keeps the
  important things close by and lets the others fall away.” și `layout.md › Visual hierarchy`: „Order
  content by relative importance.”
- **Ce nu face:** nu sunt gradienți, ilustrații sau animații decorative
  (`design-principles.md › Delight`: „Don’t mistake delight for decoration.”).

## 2. Layout și componente

Grilă de 8 px. App `100vh`. Wireframe regular (≥900 px, 1440×900):

```
┌────────┬───────────────────────────────┬────────────┐
│ ◈ Net  │  graf (SVG)                   │ scor inel  │  ← rând 1: minmax(0,1fr)
│ Acasă  │  router în centru, noduri     │  /100 + text│
│ Istoric│  ~56 px, inel severitate      │ ────────── │
│ Import │                               │ 4 indicatori│
│        │                               │ (panou: detalii/chat se suprapun│
│  RO|EN │                               │  EXACT aici, aceeași celulă)    │
│        ├───────────────────────────────┴────────────┤
│  240px │  Vulnerabilități (bandă, scroll intern)    │  ← rând 2: auto, max-height
└────────┴────────────────────────────────────────────┘
 coloane: 240px | minmax(0,1fr) | 360px   (piste fixe, nu se schimbă niciodată)
```

Compact (<900 px): sidebar → bară de sus (navigare + RO/EN pe un rând), grila într-o coloană
(graf, scor/indicatori, vulnerabilități); inspectorul devine panou jos fix, tot `position: fixed`, fără reflow.
**[judecată]** (nu am deschis `tab-bars.md`; `layout.md › Adaptability`: „Design a layout that adapts gracefully
and consistently”, iar `layout.md › Size classes` cere layout după spațiul disponibil, nu după device.)

| Decizie | Alegere | Sursă HIG |
|---|---|---|
| Navigare principală | Sidebar 240 px: logo, Acasă/Istoric/Import, activ = pilulă tonată, max. 1 nivel | `sidebars.md › Best practices`: „show no more than two levels of hierarchy”; „Consider using familiar symbols”; iconițe în culoarea de accent |
| Sidebar ascuns? | **Nu** în prima versiune. Trei destinații, nu aduce nimic | `sidebars.md › Best practices`: „Consider letting people hide the sidebar” (cu „consider”, deci opțional) → **[judecată]**, Simplicity |
| Sidebar sticky, nu ține acțiuni critice jos | Jos doar comutatorul de limbă; nicio acțiune critică acolo | `sidebars.md › Desktop`, `layout.md › Desktop (macOS)`: „Avoid placing controls or critical information at the bottom of a window” (aplicat pentru conținut; comutatorul de limbă nu e critic) |
| Comutator RO/EN | Segmented control, 2 segmente egale, text (nu mix text+iconiță), limba activă marcată, `role=radiogroup`, săgeți | `segmented-controls.md › Best practices`: „keep segment size consistent”; `› Content`: „Prefer using either text or images — not a mix”; „Use nouns or noun phrases” |
| Acțiuni pe pagină (Export, Șterge istoricul, Scanează) | Bară de acțiuni în antet, dreapta sus, aliniate vertical; puține | `toolbars.md › Best practices`: „Choose items deliberately to avoid overcrowding”; `› Actions` |
| Butoane | 4 roluri: umplut (primar), tonat (secundar), simplu, distructiv (text roșu); un singur primar per vedere; cel distructiv niciodată primar | `buttons.md › Style`: „use a button that has a prominent visual style for the most likely action”; „Use style — not size — to visually distinguish the preferred choice”; `› Role`: „Don’t assign the primary role to a button that performs a destructive action” |
| Zonă de atingere / click | ≥44×44 px la butoane și noduri (brief: ≥16 px text) | `buttons.md › Best practices`: „hit region of at least 44x44”; `accessibility.md › Mobility`: 44×44 default; stare de apăsare (`:active`) la toate, „Always include a press state” |
| Text vs iconiță pe buton | Iconiță + text; acțiuni familiare cu iconițe familiare (partajare pentru Export) | `buttons.md › Content`: „associate familiar actions with familiar icons”; „starting the label with a verb” |
| Lista Vulnerabilități | Listă grupată (inset grouped), rânduri cu iconiță în pătrat rotunjit, titlu, `IP:port`, `›`; sortată după severitate; scroll intern | `lists-and-tables.md › Style`: „grouped style uses headers, footers, and additional space to separate groups”; `› Best practices`: „Prefer displaying text in a list”; `› Content`: „Keep item text succinct”; `› Mobile`: disclosure indicator pentru drill-in |
| Rând selectat | Evidențiere persistentă (rândul și nodul) | `lists-and-tables.md › Best practices`: „a table that helps people navigate through a hierarchy persistently highlights the selected row” |
| Detalii / chat | Panou-inspector nemodal, suprapus în celula „lateral”; Esc = o stare înapoi | `sheets.md › Best practices`: „Use a nonmodal view when you want to present supplementary items that affect the main task”; `› Desktop`: „Use a panel instead of a sheet if people need to repeatedly provide input and observe results”; `popovers.md › Best practices`: „Show one popover at a time” (un singur panou deschis) |
| Panou: stări | (a) detalii, (b) chat, (c) închis; „Înapoi” + buton | `sheets.md`: „Provide an alternative to the Done button… pair it with a Cancel button or a Back button”, „Avoid showing all three” → doar „Înapoi” + închidere cu Esc |
| Confirmări (scanare, ștergere) | Dialog modal (sheet), un singur dialog; buton primar pentru acțiunea *nedistructivă*, „Anulează” mereu prezent; ștergerea = destructivă, nu primară, focus inițial pe „Anulează” | `sheets.md › Desktop`: sheet = „cardlike view with rounded corners that floats… parent window is dimmed”; `buttons.md › Role`; `design-principles.md › Agency`: „Help people recover from mistakes” |
| Meniuri de comparare | Meniuri stilizate cu etichetă și spațiere (pop-up), nu `<select>` neformatat | `popovers.md › Best practices`: popover mic pentru „a small amount of … functionality”; **[judecată]** pe forma exactă; accesibil cu tastatură |
| Grafic scor | Linie simplă, date cele mai vizibile, axe discrete; cu un singur punct → stare goală clară („Fă încă o scanare…”) | `charts.md › Best practices`: „Establish a consistent visual hierarchy… the data itself to be most prominent”; „don’t require interaction to reveal critical information” (valorile sunt și în listă) |
| Grafic: accesibilitate | Titlu + rezumat în text, etichetă pe fiecare punct (data, scor), nu doar culoare | `charts.md › Enhancing the accessibility`: „a chart often needs to offer an accessibility label for each important or interactive element”; „Avoid using subjective terms… use actual values” |
| Graful de dispozitive | SVG manual, fiecare nod `<g role=button tabindex=0>`, listă ascunsă vizual echivalentă | `accessibility.md › Mobility`: „Support mobility-related assistive technologies… Full Keyboard Access”; `charts.md › Make an interactive chart easy to navigate when using keyboard` |

## 3. Scor și indicatori (coloana laterală)
- **Inel proporțional**: arc umplut = scor/100, număr mare, „/ 100”, etichetă + iconiță („Bună”, „Mediocră”,
  „Slabă”), fără punct decorativ. Culoarea e al treilea semnal, nu primul
  (`color.md › Inclusive color`: „Avoid relying solely on color… use text labels or glyph shapes”).
- **Critică onestă (SKILL › Is it a template?):** „big number over small label” e exact hero-ul pe care skill-ul
  îl numește generic. Păstrez inelul pentru că layout-ul cerut îl impune și pentru că arcul codifică *date*
  (scor/100), nu decor. Fără gradient, fără accent luminos pe inel; culoare plată din tokenul de severitate
  + text + iconiță. Elementul memorabil rămâne **Rețeta**, nu inelul.
- 4 indicatori (Ridicată/Medie/Scăzută/Info): iconiță într-un cerc, număr, bară proporțională, etichetă.

## 4. Tokeni (revizuit după decizia ta: bleumarin + alb murdar)

Paleta e impusă de tine, nu e un default: bleumarin ca „cerneală” și culoare de acțiune, alb murdar ca suprafață.
Rămân: font de sistem sans (nu serif), fără terracotă, fără accent acid; deci nu cade în „cremă + serif + terracotă”.
Severitățile sunt singurele culori suplimentare, pentru că „colorea nu e singurul semnal” cere și text + icon,
dar codul de culoare rămâne necesar pentru scanare rapidă.

Contrast calculat din valorile hex (formula WCAG). Prag: 4.5:1 pentru tot textul
(`accessibility.md › Vision`: „Up to 17 pts — All — 4.5:1”; `dark-mode.md › Dark Mode colors`: „no lower than 4.5:1”).

| Token (rol) | Luminos | vs `surf` | vs `bg` | vs `tint` | Întunecat | vs `surf` | vs `bg` | vs `tint` |
|---|---|---|---|---|---|---|---|---|
| `--bg` alb murdar / bleumarin adânc | `#F4F1EA` | | | | `#0A1428` | | | |
| `--surf` card | `#FBFAF6` | | | | `#12203D` | | | |
| `--tint` suprafață tonată (pilule, segmente) | `#E7E2D6` | | | | `#1C2F55` | | | |
| `--label` text primar („cerneală” bleumarin) | `#14213D` | 15.29 | 14.16 | 12.36 | `#F3EFE4` | 14.06 | 15.98 | 11.52 |
| `--label-2` text secundar | `#4A5671` | 7.03 | 6.51 | 5.68 | `#B0BAD0` | 8.29 | 9.43 | 6.79 |
| `--navy` acțiune, activ, focus, arc scor | `#1B3A78` | 10.46 | 9.68 | 8.45 | `#E8E2D2` (alb murdar) | 12.50 | 14.20 | 10.23 |
| `--on-navy` text pe buton umplut | `#F4F1EA` pe `--navy` 9.68 | | | | `#0A1428` pe `--navy` 14.20 | | | |
| `--sev-high` Ridicată | `#B3201A` | 6.41 | 5.93 | 5.18 | `#FF9A90` | 7.91 | 8.99 | 6.48 |
| `--sev-med` Medie | `#9A4400` | 6.28 | 5.82 | 5.08 | `#FFB866` | 9.46 | 10.76 | 7.75 |
| `--sev-low` Scăzută | `#6F5400` | 6.83 | 6.32 | 5.52 | `#EBCB5A` | 10.17 | 11.56 | 8.33 |
| `--sev-info` Info | `#33527F` | 7.58 | 7.01 | 6.12 | `#9DBDEB` | 8.40 | 9.54 | 6.88 |
| `--good` scor „Bună” | `#1A6B2F` | 6.31 | 5.84 | 5.10 | `#6FDC88` | 9.44 | 10.73 | 7.73 |

- În dark, acțiunea primară se inversează: buton alb murdar cu text bleumarin (nu bleumarin pe bleumarin).
- **O culoare = un sens**: bleumarin/alb murdar = structură și acțiune; patru culori = doar severitate;
  `--good` = doar scor bun (`color.md › Best practices`: „Avoid using the same color to mean different things.”).
- Același set redefinit sub `prefers-color-scheme` și `prefers-contrast: more`; fără comutator de temă
  (`dark-mode.md › Best practices`: „Avoid offering an app-specific appearance setting.”).
- Abatere declarată: `color.md › System colors` („Avoid hard-coding”) nu are echivalent pe web; folosim
  tokeni pe roluri semantice (`cross-platform.md › Vocabulary`).

### Forma: „fără prea multe linii drepte” (cerința ta)
Sursa e judecata mea, ancorată în `design-principles.md › Craft`; HIG nu cere linii drepte sau curbe.
- Colțuri mari (rânduri 14, carduri 24, panou 28, pilule complet rotunde); butoane-pilulă.
- Fără borduri și fără separatoare între carduri: grupare prin suprafață tonată și spațiu
  (`layout.md › Group related items`: „negative space, container shapes, or separator lines”).
- Graful: conexiuni **curbe** (Bézier către centru), noduri circulare, inel de severitate.
- Scorul: inel cu capete rotunjite. Grafic: linie netezită, puncte rotunde.
- Singurele margini rămase: focus ring-ul și linia de severitate de pe Rețetă (informativă).

## 5. Tipografie

Stivă: `-apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", system-ui, sans-serif`.
O singură familie (`typography.md › Conveying hierarchy`: „Minimize the number of typefaces”).
Ierarhia prin greutate/dimensiune, fără greutăți subțiri (`typography.md › Ensuring legibility`:
„avoid light font weights”).

| Rol | Dimensiune / greutate | Notă |
|---|---|---|
| Large title | 34 px / 700 | titlul paginii (ex. „Rețeaua ta”) |
| Title | 22 px / 600 | titluri de card |
| Headline | 17 px / 600 | titlu de rând, titlu de panou |
| Body | 17 px / 400 | explicații, pași |
| Callout / footnote / etichete mici | **16 px** / 400–500 | peste HIG, din cauza brief-ului |
| Cifră scor | 56 px / 700 | un singur loc |

- Valorile urmează `typography.md › Ensuring legibility` (iOS 17 pt default) și nu stilurile macOS din
  `› macOS built-in text styles` (Body 13 pt), care sunt prea mici pentru public.
  Brief-ul (16 px minim) bate tabelul macOS. Conflict declarat la §8.
- Text scalabil: `rem`, fără `px` fix la text, ca zoom-ul 200% să nu rupă layout-ul
  (`accessibility.md › Vision`: „enlarge text by at least 200 percent”;
  `typography.md › Supporting Dynamic Type`).
- Etichete scurte de limbaj de 12 ani, fără jargon (`writing.md` nu a fost deschis → **[judecată]** pe ton).

## 6. Material, adâncime, formă
- **Translucid doar pe sidebar și bare**, nu pe conținut: `backdrop-filter: blur(...)` cu fundal opac de
  rezervă; sub `prefers-reduced-transparency` și `@supports not (backdrop-filter)` → fundal opac `--surf`.
  Surse: `materials.md › Liquid Glass` (stratul funcțional peste conținut), `toolbars.md › Best practices`:
  „Reduce the use of toolbar backgrounds and tinted controls”; `layout.md › Visual hierarchy`: „Differentiate
  controls from content”; `dark-mode.md`: testat cu Reduce Transparency.
  Notă: `materials.md › Standard materials`: „Thicker materials, which are more opaque, can provide better
  contrast for text” → sidebar-ul folosește material gros.
- Raze 14 / 24 / 28 px (rânduri 14, carduri 24, panou/dialog 28, butoane pilulă), concentrice cu containerul
  (`toolbars.md`: „corner radius is concentric with bar corners” → aplicat la elemente din sidebar și panou).
  **[judecată]** pentru valorile exacte.
- Fără separatoare între carduri (tonuri și spațiu); umbră moale doar pe panoul-inspector (singurul strat plutitor).
- Focus ring: 2 px `--accent`, offset 2 px, pe orice element interactiv
  (`accessibility.md › Mobility`; brief NFR-08).

## 7. Mișcare și feedback
- Două tranziții, ≤180 ms, doar `opacity` + `transform`: deschiderea/închiderea panoului-inspector. Nimic
  nu animă lățime, înălțime sau margini (cerința ta; `motion.md › Best practices`: „Add motion purposefully…
  Make motion optional”).
- `prefers-reduced-motion: reduce` → fără tranziții, schimbare instantanee. Informația nu depinde de mișcare
  (`motion.md`: „avoid using it as the only way to communicate important information”).
- Fără animație pe interacțiuni frecvente (selectarea unui nod/rând):
  `motion.md › Providing feedback`: „generally avoid adding motion to UI interactions that occur frequently”.
- **Scanare în curs:** stare „Se scanează…”, buton dezactivat, indicator **nedeterminat** (progress ring
  circular). Sursă: `progress-indicators.md › Best practices`: „When possible, use a determinate progress
  indicator… Keep progress indicators moving… Don’t switch from the circular style to the bar style…
  Display a progress indicator in a consistent location.” Nmap nu raportează procentul către API
  (cerere sincronă), deci determinat nu este posibil: **limită, nu alegere**. Descriere cu text util
  („Caut dispozitive în rețeaua ta…”), nu „Se încarcă”, conform `› Best practices`: „Avoid vague terms like loading”.
  `progress-indicators.md`: „let people halt processing”. Nu pot oferi „Anulează”, fiindcă `POST /api/scan` e
  sincron și fără endpoint de anulare. **Neacoperit**, notat la §9.
- Actualizare live: schimbările apar pe loc și sunt anunțate într-un `aria-live="polite"`
  (`charts.md › Help people notice important changes`: „highlight the changes in other ways, too”).

## 8. Asistentul AI (Întreabă AI)
Din `generative-ai.md`:
- `› Transparency`: „Communicate where your app uses AI.” → insignă „Asistent AI” vs „Din documentație”.
- `› Best practices`: „Ensure a great experience even when generative features aren’t available” → la
  404/501/eroare: mesaj real + explicația și pașii din catalog; niciun răspuns inventat.
- `› Inputs`: „Raise awareness about… hallucinations”; „offer diverse, predefined example inputs” → întrebări
  sugerate; răspunsurile arată sursele.
- `› Privacy`: „Clearly disclose how your app and its model use… personal information” → notă vizibilă
  în panou când un furnizor extern e configurat (backend-ul actual trimite IP-uri pseudonimizate, nu MAC/hostname;
  textul exact vine din `texts.js`).
- `› Outputs`: „Consider giving specific, reassuring feedback during generation” → „Caut în documentație…”.

## 9. Conflicte brief ↔ HIG și limite

| Subiect | HIG | Brief / decizie | Câștigă |
|---|---|---|---|
| Dimensiune text | macOS default 13 pt, min 10 pt (`typography.md › Ensuring legibility`) | min. 16 px peste tot | brief |
| Contrast text | 4.5:1 (<18 pt), 3:1 (≥18 pt/bold) (`accessibility.md › Vision`) | AA în ambele teme | folosesc 4.5:1 peste tot |
| Culori de sistem | „Avoid hard-coding” (`color.md`) | web → tokeni proprii pe roluri | tokeni, declarat |
| Controale jos în fereastră | evită (`layout.md › Desktop`) | banda Vulnerabilități e jos, pe toată lățimea | brief; compensat: nu conține acțiuni critice, doar listă citibilă cu scroll |
| Progres determinat | preferat (`progress-indicators.md`) | scanare sincronă | nedeterminat; mai jos |
| Anulare proces | „let people halt processing” | fără endpoint de anulare | **neacoperit** |
| Ascunderea sidebar-ului | „Consider letting people hide” | 3 destinații, sidebar fix 240 px | brief |

## 10. Legare la backend (rezumat; harta completă merge în `docs/ui-api-map.md`)

- **Sursa scanării (`live`/`import`).** Verificat în `netcheck/history.py`:
  - coloana `scans.source TEXT NOT NULL` **există deja** și `save_scan` o scrie
    (`str(analysis.get("source", analysis["file"]))`, linia ~95), deci `/api/import` și `/api/scan` pot
    seta `analysis["source"]` fără nicio migrare;
  - **dar** `list_scans()` nu o selectează (`SELECT id, file, network_score, scanned_at, status`) și
    `get_scan()` nu o returnează. Fără asta, UI nu poate afla sursa.
  - **Cea mai mică modificare aditivă, în `history.py` (AȘTEPT APROBAREA TA, nu o fac):**
    1. `list_scans`: `SELECT id, file, source, network_score, scanned_at, status`;
    2. `get_scan`: adaug `"source": scan["source"]` în dicționarul rezultat (atât ramura `error`, cât și `ok`).
    - Nicio schimbare de schemă, nicio migrare. Rândurile vechi au `source = numele fișierului`; UI tratează
      **orice valoare ≠ `"live"` ca `"import"`** (deci scanările vechi nu apar pe Acasă).
    - Risc: testele care compară `get_scan` cu un dicționar exact (`tests/test_history.py`) ar putea avea nevoie
      de câmpul nou; le actualizez.
    - Între timp (până aprobi): marcaj rezervă pe client (`localStorage`/ id-uri create de `liveScan`), cum ai cerut.
- **`GET /api/report`**: există deja în `api.py` (înainte de montarea `StaticFiles`) și are teste
  (`tests/test_api.py::test_report_is_escaped_private_and_contains_resolved_findings`). Propun să-l **extind**
  (A4 la print, scor înainte/după, tip + MAC mascat, fără hostname) în loc să-l mut într-un router nou.
  Abatere de la cerința ta; motivul: un al doilea handler pe aceeași rută ar fi cod mort.
- **`POST /api/ask`**: există în `learn_api.py`; UI-ul cade elegant dacă răspunde 404/501/eroare.
- **`GET /api/scan/preview`** (adăugat de mine mai devreme): îl folosesc *pe lângă* `GET /api/network`, ca
  butonul „Scanează rețeaua” să știe dacă rețeaua e un hotspot permis, dacă lipsește Nmap și câte porturi se scanează.
  Pe rețeaua locației (/16) butonul rămâne dezactivat, cu explicație.
- **Hostname**: `get_scan` returnează `hostname` în `devices`. UI-ul **nu îl afișează niciodată**; testul
  verifică și raportul. MAC-ul vine deja mascat (`mac_masked`).

## 11. Critica planului (SKILL › Design improvement mode, pașii 3 și 6)

**Pas 3: „Aș fi produs același plan pentru alt produs?”**
- *Cremă + serif + teracotă:* nu. Fundal rece gri-albăstrui `#F2F2F7`, font de sistem sans, accent albastru.
- *Aproape negru + un accent acid:* nu. Tema luminoasă e implicită; dark e doar semantic (`prefers-color-scheme`);
  albastrul e doar pentru acțiuni, nu e „semnătura”.
- *Ziar cu filete fine, raze 0, coloane dense:* nu. Raze 12/16/22, carduri grupate, aer generos, cap de listă
  fără filete decorative.
- *Hero „cifră mare peste etichetă mică cu gradient”:* **parțial da.** Scorul e o cifră mare. Rămâne pentru că
  (a) layout-ul îl impune, (b) arcul e dată proporțională, (c) nu are gradient. Asumat și semnalat la §3.
- *Markere 01/02/03 pe conținut care nu e secvență:* nu le folosesc. Pașii de remediere *sunt* o secvență,
  deci li se potrivește lista numerotată `<ol>`.
- Fără „eyebrow” majuscule deasupra titlurilor (cerința ta; `SKILL › Does structure encode information?`).

Planul e specific produsului prin **Rețetă** (un pericol, un prim pas) și prin tonul medical-calm al textelor;
nu l-aș fi scris la fel pentru un dashboard financiar. Păstrat.

**Pas 6: „Ce pot scoate?”** Am scos: comutatorul de temă (HIG interzice), butonul de ascundere a sidebar-ului,
animațiile de selecție, orice grafic în afara celui de evoluție. Rămân: sidebar, scor+indicatori, graf, listă,
inspector, dialoguri. Nu mai pot scoate nimic fără să pierd o cerință din brief.

**Calitate minimă (verificată în implementare):** layout fără scroll orizontal până la 360 px; focus vizibil;
`reduced-motion` + `reduced-transparency`; text la 200% zoom fără pierdere de ierarhie.

## 12. Decizii ale utilizatorului după plan
- Plan aprobat („ok”).
- `history.py`: modificarea aditivă a fost făcută (`source` în `list_scans` și `get_scan`).
- **Importul nu are istoric.** Pagina Import acceptă un lot de fișiere XML și le arată static, fără grafic de evoluție, fără comparare și fără scanare. Fișierele importate se salvează local cu `source="import"` (necesar pentru `/api/ask` și raport), dar **nu apar în Istoric și nu influențează Acasă**. Istoricul arată doar scanările `live`; de aceea insigna „Live/Import” din lista de scanări nu mai are rost și a fost scoasă.
- Schița lipsește; construit după text. Paleta: bleumarin + alb murdar (§4).

## 13. Ordinea de lucru
Accesibilitate → convenții (layout, panou fix, dialoguri) → craft (Rețeta, tokeni) → polish.
Fișiere atinse: `netcheck/web/{index.html,app.js,style.css,texts.js}`, `netcheck/api.py` (sursă live/import,
extindere raport), `docs/ui-api-map.md`, `docs/design-audit.md`, teste noi. **Neatinse:** `parser.py`,
`rules.py`, `scoring.py`, `scanner.py`, `service.py`. `history.py` doar după aprobarea ta (§10).
