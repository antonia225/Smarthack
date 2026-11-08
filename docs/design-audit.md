# NetCheck — redesign și verificare

8 noiembrie 2026. Skill: `design-rules/SKILL.md`, în improvement mode (directorul `.design-rules/` nu există). Nu a fost găsit `design-ref/`. `docs/design-plan.md` nu a fost folosit ca restricție.

## Rezumat

Designul inițial: **Needs work**. Inventarul dispozitivelor domina ecranul, dar publicul are nevoie mai întâi să înțeleagă rezultatul și următorul pas. Identitatea era aceeași pe hartă, import, istoric și stări goale; lipsea o expresie legată de rețeaua de acasă. Acestea sunt judecăți de design din codul inițial, nu defecte de securitate.

Au fost realizate trei studii HTML în `output/design-directions/`. Utilizatorul a ales **combinarea celor trei**. Implementarea finală se află în `netcheck/web/`, conectată la API-ul existent.

## Inventarul inițial și ce s-a schimbat

| Ecran / stare | Ce nu funcționa vizual înainte | Severitate | Schimbarea implementată |
|---|---|---|---|
| Acasă cu rezultat | Harta era dominantă, concluzia nu avea un loc de început | High | Rezumat cu ilustrația casei, număr de dispozitive și constatări; „Cu ce încep?” deschide prima problemă |
| Hartă | Discuri și linii fără o explicație a relațiilor; inventarul poate părea trafic real | Medium | Hartă pe suprafață opacă, contururi orbitale, explicație că liniile reprezintă inventarul; alternativă în listă |
| Scor / severități | Încă un card cu aceeași greutate; calificative reci („Mediocră”) | Medium | Scor și limitările lui într-un bloc dedicat; vocabular calm și severitate cu simbol și text |
| Probleme / remediere | Bandă densă cu titlu tehnic; pașii nu formau o poveste | High | „Ce poți face mai departe”, primul pas în prim-plan, marcaj explicit al severității |
| Detalii | Text, porturi și recomandări cu aceeași densitate | Medium | Fapte, servicii și recomandări separate prin spațiu; pași numerotați; carduri opace |
| Learning Mode — gol | Părea un formular tehnic înlocuind scorul | Medium | Titlu uman, context explicit, întrebări sugerate, explicație despre furnizor și confidențialitate |
| Learning Mode — așteptare / răspuns / eroare | Mesaje greu de diferențiat, surse vizual secundare | Medium | Mesaje distincte, etichete AI / documentație, stare de așteptare și fallback local păstrate |
| Istoric — listă / grafic | Panouri cu puțină diferențiere, progresul nu era firul principal | Medium | „Vezi ce s-a schimbat”, grafic separat, scanări selectabile și comparație cu selecții clare |
| Istoric — comparare / eroare | Diferențele păreau o listă de câmpuri | Medium | Schimbarea de scor în stil editorial, grupuri separate; eroare API păstrată |
| Istoric — conexiune indisponibilă | Eșecul încărcării nu avea feedback vizibil | High | Mesaj calm cu datele anterioare păstrate și instrucțiune de reîncercare |
| Import — gol | Zonă generică cu bordură întreruptă foarte mare | Medium | Suprafață de lucru cu titlu editorial, buton clar, format și limită explicate |
| Import — în curs / lot mixt / detaliu | Rezultatele și erorile aveau puțină ierarhie | Medium | Fișiere ca obiecte distincte, scor vizibil, mesaje per fișier, revenire la listă păstrată |
| Confirmare scanare — verificare / pregătit / blocat | Foaie utilitară fără expresie și cu fapte compacte | Medium | Dialog opac, titlu editorial, rețea / router / porturi grupate și acțiune explicită |
| Scanare în curs / erori 403, 409, 422, 500, 502 / offline | Mesaje tehnice într-o structură repetitivă | Medium | Sistem comun de feedback, pași de rezolvare și datele precedente păstrate |
| Ștergere — confirmare / eroare | Aceeași formă ca orice acțiune | Medium | Acțiune distructivă distinctă, anulare clară și avertisment despre efect; eroare în același dialog |
| Acasă / Istoric goale | Un simbol generic și text fără personalitate | High | Introducere editorială, suprafață cu spațiu generos și îndemn potrivit stării |
| Încărcare / rezultat curat / zero dispozitive | Puțină continuitate vizuală cu rezultatul normal | Medium | Aceeași limbă vizuală și aceeași structură a rezultatului, fără a sugera garanție de siguranță |
| Mobil | Panou inferior parțial și conținut de fundal încă prezent în navigare | High | Panou aproape de înălțimea disponibilă, rol dialog, fundal inert, focus ciclic, Escape și revenirea focusului |

Nu am declarat un eșec critic de contrast pentru interfața veche fără măsurători. Auditul anterior din proiect conținea verificări parțiale; rezultatele de mai jos privesc implementarea nouă.

## Principii citite și aplicate

Referințele sunt locale, din skill. Pentru aplicația web se aplică principiile, nu obligația de a folosi componente native macOS.

- `layout.md › Visual hierarchy`: „Order content by relative importance.” Rezumat → inventar → acțiune, cu zona laterală stabilă.
- `typography.md › Conveying hierarchy`: „Minimize the number of typefaces you use”. Sistemul pentru comenzi și text, Georgia doar pentru titluri editoriale.
- `accessibility.md › Vision`: „Convey information with more than color alone.” Severități cu simbol, text și etichetă accesibilă.
- `liquid-glass.md › The two layers`: „Functional layer”. Translucența este limitată la navigare; conținutul și dialogurile rămân opace.
- `motion.md › Best practices`: „Make motion optional.” Fade scurt, fără deplasarea grilei; animațiile dispar cu reduced motion.
- `generative-ai.md › Best practices`: „consider offering a non-AI fallback.” Explicația locală și sursele rămân disponibile.
- `sheets.md › Anatomy`: „Cancel (or Close)”. Dialogurile au ieșire explicită și tastatura browserului.

## Direcția combinată

Identitate: **casa conectată, explicată cu grijă**. Semnătura este o casă desenată din conexiuni, nu un scut generic. Harta provine din „Semnal”, iar titlurile și remedierea din „Ghid”. Am exclus violetul ca al doilea accent de brand: ar concura cu indicatorii de risc. Am eliminat blurul din fundalul dialogurilor și mișcarea de translație a panoului; fade-ul păstrează geometria exactă.

| Rol | Light | Dark | Contrast relevant light / dark |
|---|---|---|---|
| Fundal | `#EDF3EF` | `#10241D` | — |
| Suprafață | `#FFFFFF` | `#1A3027` | — |
| Text principal | `#193D32` | `#EDF6EE` | 11,97 / 12,71 pe suprafață |
| Text secundar | `#52685B` | `#B6CABA` | 6,02 / 8,12 pe suprafață; 4,97 / 6,06 pe nuanță |
| Acțiune | `#245F49` | `#A1DDB9` | 7,48 / 9,84 cu textul butonului |
| Nuanță de grupare | `#E1ECE5` | `#2A4537` | vezi textul secundar |

Semnalele de risc rămân tokeni semantici separați; raportul `output/ui-redesign/contrast.json` conține perechile și valorile. Minimul perechilor de text verificate este 4,97:1. Nu este o certificare WCAG completă.

Tipografie: corp 17 px; note, date și etichete minimum 16 px; subtitluri 22–28 px; titlul paginii 28–40 px; scor 44 px cu cifre tabulare. Fonturi locale de sistem; fără fonturi descărcate. Colțuri 12–28 px, suprafețe solide, umbre rare. Mișcare: fade de 120 ms pentru panou și feedback de 180 ms pentru comenzi; fără animație de intrare repetată pe conținut.

```text
Regular (1440)
[nav] [titlu + scanare                         ]
[   ] [casă + rezumat + primul pas             ]
[   ] [hartă / listă                 ][scor    ]
[   ] [                             ][        ]
[   ] [ce poți face mai departe      ][severit.]

Compact (390)
[brand · limbă]
[Acasă · Istoric · Import]
[titlu / scanare]
[casă / concluzie / primul pas]
[scor / severități]
[hartă sau listă]
[ce poți face mai departe]
[detalii / chat: dialog când e deschis]
```

## Contractul păstrat

Backend-ul, scannerul și guardrail-ul nu au fost modificate. Sunt păstrate endpoint-urile, id-urile, selectoarele cerute de teste și `netcheck:cleared`. Acasă folosește doar sursa `live`, importul rămâne separat, polling-ul este la 5 s. Confirmarea scanării trimite tot `confirm: true`. Datele sunt construite cu DOM + `textContent`, fără HTML injectat din API.

Au fost adăugate teste de browser pentru lista dispozitivelor, focusul mobil, redimensionarea cu panoul deschis și actualizarea noilor texte RO/EN. Dicționarele au 186 chei fiecare, fără chei lipsă.

## Verificare și limite

- `python -m pytest -q -m "not native"`: **317 passed, 1 deselected**, cu o avertizare de depreciere Starlette/httpx. Rulat cu Python 3.12, Playwright și Chrome real într-un mediu temporar. Avertizarea nu este o eroare de UI.
- `tests/test_ui_layout.py` și `tests/test_ui_api_contract.py` sunt incluse; verifică geometria stabilă, CLS, polling, separarea importului, textul minim, navigarea și contractul API.
- 144 capturi: zero excepții JavaScript, zero texte detectate sub 16 px și zero depășiri orizontale la dimensiunile cerute.
- EN pentru cele trei pagini principale în ambele teme și dimensiuni; Acasă cu fontul de bază mărit la 200% fără depășire orizontală. Această verificare nu echivalează cu validarea tuturor stărilor la 200%.
- `node --check` pentru JS și `git diff --check`: fără erori.


Capturi și rezultate: `output/ui-redesign/index.html`, `manifest.json`, `checks.json`, `supplemental-checks.json`, `contrast.json`. Matrice: 36 stări × 2 dimensiuni × 2 teme = 144 capturi de viewport, plus variante complete de pagină pe mobil și capturi EN pentru cele trei pagini principale. Erorile, progresul și confirmarea pregătită sunt simulate la nivel HTTP în browser; datele normale, istoricul și importul provin din API-ul real, cu o bază temporară și XML-urile de validare. Nu au fost pornite scanări și nu a fost ștearsă baza utilizatorului.

Manifestul marchează stările simulate. Verificările automate pentru fiecare captură urmăresc excepțiile JavaScript, textul sub 16 px și depășirea orizontală. Numărul de capturi nu înseamnă inspecție manuală individuală: verificarea vizuală a urmărit ecranele principale și planșele de contact.

Nu sunt verificate: scanare Nmap/Npcap live, furnizor LLM extern, VoiceOver / NVDA, dispozitive iOS/Android fizice, certificare WCAG completă, toate combinațiile de 256 dispozitive și toate textele API posibile. Testele normale nu produc trafic de scanare; testul nativ este exclus deliberat.

## Ajustare ulterioară — panouri și hartă

La cererea utilizatorului, banda cu casa și concluzia a fost eliminată din rezultatele reale. Harta urcă sub antet. Scorul rămâne în dreapta, iar blocul de severități este înlocuit de starea „Nu ai selectat un dispozitiv” și, după selecție, de detaliile lui. Detaliile nu mai sunt un overlay sau un dialog mobil; pagina se derulează normal, fără scroll în lista vulnerabilităților sau corpul detaliilor. Testele pentru vechea geometrie de overlay au fost înlocuite cu verificări pentru acest comportament solicitat.

Harta are zoom limitat la 50–300%, resetare, drag pe fundal, zoom cu Ctrl/Cmd + rotița și comenzi de tastatură (+/−, săgeți, 0). Scrollul obișnuit continuă să deruleze pagina. Comenzile sunt mai compacte pentru mouse, păstrând ținte tactile de 44 px. Capturile actualizate sunt în `output/ui-panels/`; galeria anterioară documentează versiunea precedentă.
