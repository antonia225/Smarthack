# Learning Mode — baza de cunoștințe (Faza 2a)

`knowledge/sources.json` este allowlistul explicit: 15 subiecte pentru codurile
catalogului, toate cele **12 concepte enumerate** în cerință (deși titlul spune
10), patru pagini CISA/NIST/OWASP, MDN HTTP și două RFC-uri. Total: 34 documente.
Cloudflare, Professor Messer și Bitdefender nu sunt descărcate sau copiate.

```sh
# Refolosește documentele/cache-ul existente; descarcă doar sursele lipsă:
python scripts/build_knowledge.py
# Reconstruiește exclusiv local, inclusiv într-un checkout fără .cache:
python scripts/build_knowledge.py --offline
# Numai pentru o actualizare deliberată a tuturor surselor:
python scripts/build_knowledge.py --refresh
```

Builderul folosește numai stdlib, User-Agent `NetCheck-LearningMode/2.0`, cereri
secvențiale cu pauză și cache local în `.cache/` (ignorat de Git). Nu reîncearcă
automat HTTP 429; raportează `Retry-After`. Pentru 404 sau titlu Wikipedia lipsă,
raportează explicit documentul și continuă. Exit 0 înseamnă toate documentele
reușite; exit 1 înseamnă corpus parțial, fără text substituit sau inventat.
O rerulare normală reutilizează descărcările reușite. După o eroare 429, așteaptă
intervalul indicat înainte să rerulezi comanda.

Fiecare `<id>.md` are front matter cu valori JSON (compatibile YAML): `id`,
`source_url`, `license`, `attribution`, `revision`, `retrieved`, `codes`,
`keywords_en`, `keywords_ro`, plus titlu, limba originală și URL final HTTPS.
Wikipedia este citită prin API cu revizie și timestamp; pentru celelalte pagini
se înregistrează SHA-256 al răspunsului, ETag/Last-Modified când sunt disponibile
și identificatorul RFC unde există. Lipsa unei revizii editoriale nu este
mascată de un număr inventat. Consultați [NOTICE](../docs/NOTICE.md) pentru
atribuiri, versiuni și starea fiecărui document.

Textul extras este împărțit fără completări sau repetări în pasaje de 80–200
cuvinte, `kb:<id>#n`. Un document prea scurt este raportat ca indisponibil.
`index.json` conține pasajele, metadatele, stările surselor și acoperirea
codurilor: pasajele existente sau marcajul exact „fără documentație încă”.
Pasajele păstrează limba originală; nu sunt traduceri generate. Pasajele extrase
pot păstra titluri, referințe sau alte secțiuni auxiliare din documentul sursă.

Retrieverul citește numai indexul allowlistat, normalizează diacriticele și
majusculele și aplică BM25 lexical determinist. Caută în text, titlu,
`keywords_ro`, `keywords_en`, coduri și textele ambelor limbi din catalog.
Returnează cel mai bun pasaj per document, pentru diversitate în top 3.
Catalogul local rămâne o sursă distinctă (`catalog:CODE`) și funcționează când
corpusul lipsește; nu este prezentat drept text Wikipedia.

`keywords_ro` sunt etichete editoriale de căutare, nu traduceri ale pasajelor.
Toate cele 34 de liste sunt completate; utilizatorul nu are câmpuri obligatorii
rămase de completat. Sinonimele proprii pot fi adăugate în manifest și reindexate
cu `--offline`, fără o nouă descărcare.

## Verificare din 8 noiembrie 2026

- Builder live: **34/34 documente, 642 pasaje, exit 0**.
- Reconstrucție offline: **34/34 documente, 642 pasaje, exit 0**; Markdown-ul,
  indexul și NOTICE rămân identice octet cu octet la rerulare.
- Descărcări rămase indisponibile: **niciuna**. Erorile inițiale HTTP 429 au fost
  depășite prin reluare ulterioară din cache; URL-ul OWASP 404 a fost corectat.
- Pytest complet: **262 passed, 1 skipped, 1 warning** (deprecare Starlette/httpx).
- Toate cele 15 coduri au pasaje; toate URL-urile de metadate folosesc HTTPS.
- Cele 20 de întrebări (10 RO, 10 EN) trec în top 3 pe fixture-uri atribuite și,
  separat, pe corpusul complet descărcat. Fixture-urile acoperă cinci finding-uri
  și cinci concepte; nu depind de internet.

```sh
python -m pytest tests/test_retrieval.py tests/test_knowledge.py -q
python -m pytest -q
```

Parserul, regulile, scoringul și istoricul nu sunt modificate de această fază.
