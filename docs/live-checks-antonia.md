# Verificări live Antonia / Antonia live checks

Rulează comenzile doar în laboratorul autorizat și după confirmarea IP-urilor.

## 4 — guardrail

```sh
python -m netcheck demo-refusals
python -m netcheck network
python -m netcheck scan 8.8.8.8 --confirm
python -m netcheck scan --confirm
```

`demo-refusals` trebuie să arate refuz pentru IP public, Wi-Fi de locație și
lipsa confirmării. Scanarea publică trebuie refuzată fără trafic; ultima
comandă este permisă doar după `configure-lab`. Pentru juriu: „Aplicația cere
confirmare și refuză ținte publice, în afara allowlist-ului sau a LAN-ului.”

## 6 — BEFORE/AFTER

```sh
python -m netcheck configure-lab --allow <SUBNET> --confirm
python -m netcheck lab-run --label before <IP-SAU-CIDR> --confirm
python scripts/lab-verify.sh
# remediați serviciile pe gazdă
python -m netcheck lab-run --label after <IP-SAU-CIDR> --confirm
python scripts/lab-verify.sh
```

Nu modificați XML-urile și nu declarați scorul înaintea motorului oficial.
Pentru juriu: „Păstrez capturi BEFORE și AFTER comparabile și compar doar
findings observate, fără rezultate inventate.”

## 7 — secrete

```sh
sh scripts/macos/check-secrets.sh
```

Pe Windows:

```powershell
.\scripts\windows\check-secrets.ps1
```

Rezultatul așteptat este cod 0 fără raportări; gitleaks se instalează separat.
Pentru juriu: „Verific working tree-ul și istoricul, iar CI repetă verificarea
pe push și PR.”
