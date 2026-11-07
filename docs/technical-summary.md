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

Motorul de analiză, findings, scorul și UI-ul sunt **TODO (Georgiana / colega
frontend)**.
