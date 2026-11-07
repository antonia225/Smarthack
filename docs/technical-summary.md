# Netcheck — sumar tehnic / technical summary

## Laborator / Lab

Scannerul este laptopul macOS conectat la hotspot; țintele sunt laptopurile și
serviciile autorizate. IP-urile, interfețele și prefixele se verifică în fiecare
sesiune și se notează în [`lab/session-template.md`](../lab/session-template.md).

## Scanner și guardrail

`scanner.py` detectează rețeaua locală, validează strict IPv4 RFC1918, allowlist,
prefix maxim `/24`, confirmarea și revalidarea LAN-ului înainte de proces.
Comanda Nmap este fixă: TCP top 1.000 din `nmap-services`, UDP-urile cerute,
identificare servicii, `http-title`, limită de rată și timeout. Pe macOS, sudo
poate invoca numai wrapperul root-owned cu cale XML UUID și argumente fixe.
`scan --confirm` fără țintă folosește subnetul persistat al laboratorului.

## Presupuneri și limitări / assumptions and limits

Configurația IP nu autentifică proprietarul hotspot-ului. Scanarea reală,
privilegiile macOS, firewall-ul, timpul pentru `/24` și rezultatele BEFORE/AFTER
rămân NEVERIFICAT până la rularea manuală. XML-ul brut poate conține date locale.
Nu se folosește LLM în scanner; deciziile sunt deterministe.

Motorul de analiză, findings și scorul rămân deterministe și independente de
LLM. UI-ul include Learning Mode și raportul HTML pentru furnizorul IT.

## LLM use

Learning Mode uses an optional, evidence-grounded LLM only to explain an
already computed scan. The provider receives pseudonymized device labels,
device type, IP, service names, ports, finding codes, severities and score,
as well as the unfiltered user question and retrieved passages; MAC addresses, hostnames, raw
banners, and HTTP titles are excluded. It never creates findings, severities,
scores, or remediation decisions. Missing credentials, network failure, timeout,
provider error, or validator rejection returns the local catalog/documentation
fallback. See [`learning-mode.md`](learning-mode.md).

Pseudonymization is not anonymization. A missing corpus does not disable a
configured provider. Validation is heuristic and does not prove semantic
correctness. Citation IDs must match the supplied evidence or retrieved passages. Browser accessibility, full RO/EN coverage,
and live provider verification remain subject to the explicit verification
record in `learning-mode.md`. The corpus builder completed successfully for
all 34 Phase 2a documents (642 passages), with revision metadata and offline
rebuild verification.
