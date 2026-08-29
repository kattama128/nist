# Fixture NVD

Risposte dell'API NVD 2.0 **reali ma ridotte**: struttura originale (`resultsPerPage`,
`startIndex`, `totalResults`, `vulnerabilities[].cve`) con i campi non usati rimossi
(traduzioni, `cveTags`, riferimenti in eccesso, `matchCriteriaId` accorciati).
Servono a far girare tutti i test **completamente offline**.

| File | CVE | Caso coperto |
|------|-----|--------------|
| `cve_exact_version.json` | CVE-2021-41773 | versione esatta (`http_server:2.4.49`), due metriche CVSS (v3.1 + v2) |
| `cve_version_range.json` | CVE-2022-22720 | range `versionStartIncluding` + `versionEndExcluding` |
| `cve_and_configuration.json` | CVE-2019-0232 | configurazione `operator: "AND"` con due nodi (Tomcat **su Windows**), incluso un `cpeMatch` con `vulnerable: false` |
| `cve_no_configurations.json` | CVE-2023-4128, CVE-2024-99999 | CVE rifiutata e CVE in attesa di analisi: nessun `configurations`, nessuna metrica |
| `cve_all_versions.json` | CVE-2011-2523 | CPE di prodotto senza versione ne' vincoli -> `match_type = all_versions` |

## Adattamenti dichiarati

Due record si discostano dal dato NVD attuale, per coprire rami di codice che
altrimenti resterebbero senza fixture:

* **CVE-2022-22720**: NVD esprime il limite superiore come
  `versionEndIncluding: "2.4.52"`; qui e' scritto come l'equivalente
  `versionEndExcluding: "2.4.53"`, richiesto per testare quel vincolo.
* **CVE-2011-2523**: NVD cataloga il CPE esatto `beasts:vsftpd:2.3.4`; qui il CPE
  e' allargato a `beasts:vsftpd:*` senza vincoli di versione, per riprodurre il
  caso `all_versions` (CPE privo di qualsiasi indicazione di versione).

* **CVE-2024-99999** non esiste: e' un segnaposto che riproduce la forma di una
  CVE appena pubblicata e non ancora analizzata.
