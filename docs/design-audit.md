# Audit de design

Status: **parțial**. Ce a fost verificat automat (Chrome real, `tests/test_ui_layout.py`) și ce nu.

## Verificat automat
- 1440×900: Acasă fără scroll de pagină; sidebar, grafic, bandă și celula laterală au bbox identic (0 px) înainte/după deschiderea panoului; CLS = 0; panoul acoperă exact celula „lateral".
- Orice text vizibil ≥ 16 px; niciun hostname în DOM.
- Acasă se actualizează fără reload când apare un scan live nou.
- Import (lot de 2 fișiere, unul stricat) nu schimbă Acasă.
- 390×844: fără scroll orizontal.

## Ce / De ce / Fix (principii HIG adaptate)
| Ce | De ce | Fix |
|---|---|---|
| Paletă bleumarin + alb murdar, fără borduri între carduri | Clarity / Deference; cerută de utilizator | tokeni în `style.css`, contraste AA calculate în `docs/design-plan.md` |
| Text minim 16 px | Brief-ul bate HIG | fără corp de 11–13 px |
| Severitate = pictogramă + text | Culoarea nu e singurul semnal | `sev-*` symbols |
| Panou ca overlay peste celula „lateral" | zero reflow | `opacity/transform`, `contain: layout paint` |
| Mișcare redusă / transparență redusă | Accesibilitate | media queries dedicate |

## Neverificat (spune-o clar)
- Capturile 1440×900 / 390×844 light/dark pentru toate stările (Import după încărcare, foaia de confirmare, foaia de ștergere) — nu au fost refăcute după ultimele ajustări CSS.
- Navigarea doar cu tastatura și comutarea RO/EN: acoperite doar manual/parțial.
- Scanare live reală (Nmap/Npcap lipsesc pe acest laptop; rețeaua locală e Wi-Fi-ul sălii, refuzată corect).
- Schița originală nu a fost furnizată; layoutul urmează textul.
