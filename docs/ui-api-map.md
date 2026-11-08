# UI ↔ API

| Acțiune în UI | Endpoint | Succes | Erori → comportament UI |
|---|---|---|---|
| Acasă: încărcare / poll la 5 s | `GET /api/scans`, `GET /api/scans/{id}` | Ia cel mai nou scan cu `source == "live"`; actualizează doar dacă id-ul s-a schimbat | rețea indisponibilă → mesaj calm, ultimele date rămân |
| „Scanează rețeaua" (foaia de confirmare) | `GET /api/network`, `GET /api/scan/preview` | Arată rețeaua, ținta și porturile | 409 `network_detection_failed` → pași de rezolvare; ținta `null` + `problems` → buton dezactivat |
| Confirmare scanare | `POST /api/scan {target?, confirm:true}` | 200 → grafic nou, anunț „Scanare nouă: scor X" | 403 `permission_denied` → explicație; 409 `network_detection_failed`; 409 (ocupat) → „deja în curs"; 502 `scan_failed` → pași (Nmap/Npcap); 500 `operation_failed`; 422 → eroare generică; rețea → „nu pot ajunge la aplicație" |
| Istoric: listă | `GET /api/scans` (filtrat live) | listă + grafic scor | listă goală → stare goală |
| Istoric: comparare | `GET /api/compare?a=&b=` | diferențe | 400 / 404 → mesaj |
| Istoric: Export | `GET /api/report?lang=&a=&b=` | HTML pentru A4 | 400 / 404 / 422 → mesaj |
| Șterge istoricul | `DELETE /api/history` | listă goală, eveniment `netcheck:cleared` | eroare → mesaj |
| Import (lot de fișiere) | `POST /api/import?filename=` (secvențial) | Afișare statică; scanarea se salvează local în baza de date cu `source = "import"` (necesar pentru „Întreabă AI" și raport), dar nu apare în Acasă și Istoric | `status: error` (XML stricat) → raportat pe fișier, restul continuă |
| Întreabă AI | `POST /api/ask {scan_id, device_ip, question, lang}` | răspuns + surse | 404/400/422 sau indisponibil → mesaj, nu se inventează răspunsuri |

Acasă și Istoric citesc doar scanările `live`; scanările importate rămân în baza locală (se șterg cu „Șterge istoricul"), dar nu le influențează.
