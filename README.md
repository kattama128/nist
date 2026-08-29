# nvdlocal

Mirror locale del database vulnerabilità del **NIST NVD** con lookup delle CVE per
**software + versione**. Pensato per il lavoro SOC / vulnerability assessment: dopo il
fingerprint di un servizio esposto (`Apache httpd 2.4.52`, `OpenSSH 8.2p1`,
`nginx 1.18.0`) dice subito quali CVE lo riguardano, con severità, sfruttamento noto
(CISA KEV) e probabilità di sfruttamento (EPSS).

Dopo la sincronizzazione iniziale **funziona completamente offline** e processa un
inventario di più host in batch.

---

## Indice

- [Installazione](#installazione)
- [API key NVD](#api-key-nvd)
- [Prima sincronizzazione: tempi e spazio](#prima-sincronizzazione-tempi-e-spazio)
- [Comandi](#comandi)
- [I quattro `match_type` e i loro limiti](#i-quattro-match_type-e-i-loro-limiti)
- [Risoluzione del nome prodotto](#risoluzione-del-nome-prodotto)
- [Exit code](#exit-code)
- [Architettura](#architettura)
- [Schema del database](#schema-del-database)
- [Test](#test)
- [Scelte implementative e limiti noti](#scelte-implementative-e-limiti-noti)

---

## Installazione

Richiede **Python 3.11+**.

```bash
git clone <questo-repo> && cd nist
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .            # installa il comando 'nvdlocal'
# oppure, senza installare il package:
pip install -r requirements.txt && python -m nvdlocal --help
```

`fastapi` e `uvicorn` servono solo al comando `serve`, `openpyxl` solo all'export
`.xlsx` di `batch`: entrambi sono in `requirements.txt` ma il resto funziona anche
senza.

### Configurazione

```bash
cp .env.example .env        # poi valorizza NVD_API_KEY
```

| Variabile | Default | Descrizione |
|---|---|---|
| `NVD_API_KEY` | *(vuota)* | API key NVD. Nessun segreto è hardcoded: si legge da ambiente o `.env`, mai dal codice. |
| `NVDLOCAL_DB` | `~/.local/share/nvdlocal/nvd.db` | Percorso del database. Sovrascrivibile anche con `--db`. |

Il file `.env` è in `.gitignore`; è versionato solo `.env.example`.
I log applicativi finiscono su stdout e su `nvdlocal.log`, accanto al database.

---

## API key NVD

L'API key è **facoltativa ma fortemente consigliata**: alza il rate limit da
**5 richieste ogni 30 secondi** a **50 ogni 30 secondi**, cioè da ~25 minuti a ~3
minuti di sincronizzazione completa.

1. Vai su <https://nvd.nist.gov/developers/request-an-api-key>
2. Compila il form (nome, email, organizzazione) e accetta i termini
3. La chiave arriva via email in pochi minuti
4. Mettila in `.env` come `NVD_API_KEY=...`, oppure passala con `--api-key`

Il client applica una pausa conservativa fra richieste: **6 s senza key**,
**0,8 s con key**, ben sotto il limite dichiarato.

---

## Prima sincronizzazione: tempi e spazio

L'API NVD 2.0 pagina a un massimo di **2000 risultati per richiesta** e il catalogo
supera le **300.000 CVE**, quindi servono circa **150 richieste**.

| | Senza API key | Con API key |
|---|---|---|
| Pausa fra richieste | 6 s | 0,8 s |
| Solo attesa rate limit | ~15 min | ~2 min |
| **Tempo totale realistico** | **20-30 min** | **5-8 min** |

Il tempo totale è superiore alla sola attesa perché a ogni pagina si aggiungono
download (~10-20 MB), parsing JSON e scrittura su SQLite.

**Spazio su disco: circa 2 GB**, di cui la maggior parte è la colonna `raw_json`
(il blob NVD originale di ogni CVE). Serve a non dover risincronizzare 300.000 CVE
quando cambia la logica di parsing: basta rileggere `raw_json`. Considera anche il
file `-wal` durante la sync.

L'API NVD è notoriamente instabile: 403/429/503 e timeout sono ritentati fino a
**5 volte** con backoff esponenziale da 10 s a 120 s. Se la sync si interrompe
comunque, lo `startIndex` raggiunto è salvato nella tabella `meta` dopo **ogni
pagina**: `sync --full --resume` riparte da lì senza riscaricare nulla.

```bash
nvdlocal sync --full                 # prima sincronizzazione (lunga)
nvdlocal sync --full --resume        # riprende una sync interrotta
nvdlocal sync --incremental          # aggiornamento quotidiano (secondi/minuti)
nvdlocal sync --enrich               # solo CISA KEV + EPSS
```

Dopo la prima sync, tienila aggiornata con `sync --incremental` (per esempio da
cron ogni notte): usa `lastModStartDate`/`lastModEndDate` partendo dall'ultima sync
**meno un'ora** di margine. La finestra massima ammessa dall'API è di **120 giorni**:
se l'ultima sync è più vecchia, la richiesta viene spezzata automaticamente in più
finestre. L'arricchimento KEV/EPSS parte in automatico dopo ogni sync incrementale.

---

## Comandi

### `sync` — sincronizzazione

```bash
nvdlocal sync --full [--resume] [--api-key KEY] [--max-pages N]
nvdlocal sync --incremental
nvdlocal sync --enrich
```

`--max-pages` limita il numero di pagine scaricate: utile per una sincronizzazione
parziale di prova senza aspettare mezz'ora.

### `search` — la ricerca principale

```bash
# Il caso d'uso tipico dopo un fingerprint
nvdlocal search --product httpd --version 2.4.52

# Disambiguando il vendor
nvdlocal search --product http_server --version 2.4.52 --vendor apache

# Partendo da un CPE completo (la versione si prende dal CPE)
nvdlocal search --cpe "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"

# Solo quello che conta davvero in un triage
nvdlocal search -p openssh -V 8.2p1 --min-severity HIGH --only-kev
nvdlocal search -p nginx   -V 1.18.0 --min-score 7.0 --min-epss 0.1

# Escludendo i match "all_versions", spesso rumorosi
nvdlocal search -p vsftpd -V 3.0.3 --no-include-all-versions

# Output per altri strumenti
nvdlocal search -p httpd -V 2.4.52 --format json
nvdlocal search -p httpd -V 2.4.52 --format csv --output report.csv
```

Esempio di output:

```
                                 CVE applicabili a httpd 2.4.52 (1)
┏━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━┳━━━━━┳━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┓
┃ CVE            ┃ Score ┃ Severita' ┃ KEV ┃ EPSS ┃ Match ┃ Versioni           ┃ Pubblicata ┃ CWE     ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━╇━━━━━╇━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━┩
│ CVE-2022-22720 │   9.8 │ CRITICAL  │  -  │    - │ range │ >= 2.4.0, < 2.4.53 │ 2022-03-14 │ CWE-444 │
└────────────────┴───────┴───────────┴─────┴──────┴───────┴────────────────────┴────────────┴─────────┘
```

Le CVE presenti in **CISA KEV** sono evidenziate in rosso. L'ordinamento è per score
decrescente, poi per data di pubblicazione decrescente.

La tabella è una vista di sintesi; `--format json` e `--format csv` (e il comando
`show`) riportano **tutti** i campi di ogni risultato: CVE ID, score, severità,
vettore CVSS, CWE, KEV, EPSS, data di pubblicazione, `match_type`, la stringa CPE che
ha prodotto il match e il range di versioni coinvolto.

### `resolve` — dal nome commerciale al CPE

```bash
nvdlocal resolve "apache http"
nvdlocal resolve nginx
nvdlocal resolve exchange --limit 10
```

```
                         Candidati per 'apache http'
┏━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━┓
┃ Vendor ┃ Product     ┃ CPE                                          ┃ CVE ┃
┡━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━┩
│ apache │ http_server │ cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:* │   2 │
└────────┴─────────────┴──────────────────────────────────────────────┴─────┘
```

### `batch` — inventario di più host

```bash
nvdlocal batch --input inventory.csv --output risultati.xlsx
nvdlocal batch --input inventory.csv --output risultati.csv --min-severity HIGH
```

L'inventario è un CSV con colonne `host,port,vendor,product,version`
(`host`, `port` e `vendor` possono essere vuoti):

```csv
host,port,vendor,product,version
srv-web-01,443,apache,http_server,2.4.52
srv-web-02,80,,httpd,2.4.49
srv-app-01,8080,apache,tomcat,9.0.10
srv-ftp-01,21,,vsftpd,3.0.3
```

Il report `.xlsx` ha due fogli:

- **`risultati`** — una riga per ogni coppia *(host, CVE)*, con
  `host / port / software / versione / cve / score / severity / kev / epss /
  match_type / range_versioni / cpe / descrizione`. Le righe in KEV sono evidenziate.
- **`non_risolti`** — le righe di inventario che non è stato possibile risolvere, con
  il motivo (prodotto sconosciuto, prodotto ambiguo con l'elenco dei candidati,
  versione mancante, nessuna CVE applicabile).

Se il file di output non ha estensione `.xlsx` vengono scritti due CSV affiancati
(`risultati.csv` e `risultati_non_risolti.csv`), così il comando funziona anche senza
`openpyxl`.

### `show` — dettaglio di una CVE

```bash
nvdlocal show CVE-2021-41773
```

Mostra date, stato, CVSS completo con vettore, CWE, stato KEV/EPSS, descrizione,
**tutte** le configurazioni CPE con i relativi range e i riferimenti.

### `stats` — stato del database

```bash
nvdlocal stats
```

Numero di CVE e di righe `cpe_match`, CVE in KEV, score EPSS, ultima sync,
dimensione su disco, eventuale checkpoint di resume, distribuzione per severità e
top vendor per numero di CVE.

### `serve` — API HTTP (opzionale)

```bash
nvdlocal serve --port 8000
curl "http://127.0.0.1:8000/search?product=httpd&version=2.4.52"
```

| Endpoint | Descrizione |
|---|---|
| `GET /search?product=&version=&vendor=` | Ricerca; accetta anche `cpe`, `min_severity`, `min_score`, `only_kev`, `min_epss`, `include_all_versions`. Prodotto ambiguo → **409** con l'elenco dei candidati; sconosciuto → **404** |
| `GET /resolve?term=` | Candidati `vendor:product` |
| `GET /cve/{cve_id}` | Dettaglio di una CVE |
| `GET /cpe/parse?cpe=` | Parsing di una stringa CPE 2.3 |
| `GET /health` | Stato del servizio, numero di CVE, ultima sync |

Documentazione interattiva su `/docs`.

---

## I quattro `match_type` e i loro limiti

Ogni risultato è etichettato con il **motivo** per cui è stato considerato
applicabile. Sono livelli di confidenza diversi e vanno letti diversamente.

### `exact` — massima confidenza

Il CPE indica una versione concreta identica a quella cercata
(`cpe:2.3:a:apache:http_server:2.4.49:*` con input `2.4.49`).

**Limite**: il confronto è sulla versione *upstream*. Una `2.4.49-1ubuntu1` con la
patch di distribuzione già applicata risulta comunque vulnerabile, perché il
backporting delle patch non è rappresentato nei CPE. Su sistemi con pacchetti di
distribuzione va incrociato con l'advisory del vendor (DSA/USN/RHSA).

### `range` — alta confidenza

Il CPE ha versione `*` e almeno un vincolo di range; tutti i vincoli presenti sono
soddisfatti in AND:

| Vincolo | Condizione |
|---|---|
| `versionStartIncluding` | `input >= valore` |
| `versionStartExcluding` | `input > valore` |
| `versionEndIncluding` | `input <= valore` |
| `versionEndExcluding` | `input < valore` |

**Limite**: stesso discorso del backporting, più la qualità della catalogazione NVD.
I range sono a volte più larghi della realtà (per prudenza dell'analista NVD).

### `all_versions` — bassa confidenza, da verificare

Il CPE ha versione `*` e **nessun** vincolo di range: formalmente la CVE riguarda
*tutte* le versioni del prodotto.

**Limite**: sono spesso CVE mal catalogate (l'analista non ha specificato le versioni
affette) oppure genuinamente universali. Vengono incluse di default ma marcate, e
l'output stampa un promemoria del loro numero. In un triage con molto rumore,
escludile con `--no-include-all-versions` — ma sappi che così puoi perdere CVE reali.

### `conditional` — vulnerabile **solo se** c'è anche altro

La configurazione padre ha `operator: "AND"` con più nodi: la vulnerabilità richiede
la presenza contemporanea di un altro componente. L'esempio classico è
**CVE-2019-0232**, che colpisce Apache Tomcat *solo su Windows* e solo con
`enableCmdLineArguments` abilitato.

L'output riporta quali altri CPE compongono la condizione:

```
╭── Match condizionali (configurazione AND: serve un altro componente) ──╮
│ CVE-2019-0232  cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*                 │
│     + richiede anche: cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*      │
╰───────────────────────────────────────────────────────────────────────╯
```

**Limite**: questi match **non vanno presentati come certi**. Non sono scartati
perché la condizione potrebbe essere soddisfatta, ma la verifica è manuale.
Nota che i CPE *dentro* lo stesso nodo `OR` sono alternative fra loro, non requisiti:
come condizione vengono riportati solo gli **altri nodi** dell'AND.

### Cosa viene sempre escluso

- Le righe con **`vulnerable: false`**: nei CPE descrivono il contesto ("running on"),
  non il componente vulnerabile. Un match su di esse produrrebbe falsi positivi
  massicci — cercare `microsoft:windows` non deve restituire tutte le CVE di ogni
  applicativo che gira su Windows.
- Le righe di un nodo **negato** (`negate: true`).
- Le CVE senza `configurations` (rifiutate o in attesa di analisi) sono salvate nel
  database — così `show` le trova — ma non producono match.

---

## Risoluzione del nome prodotto

Gli utenti scrivono `apache`, `httpd`, `Apache HTTP Server`; il CPE è
`apache:http_server`. La risoluzione procede in tre passi:

1. **Alias noti** — dizionario in `nvdlocal/cpe.py`:

   | Alias | CPE |
   |---|---|
   | `httpd`, `apache2` | `apache:http_server` |
   | `openssh`, `sshd` | `openbsd:openssh` |
   | `nginx` | `f5:nginx` **e** `nginx:nginx` |
   | `iis` | `microsoft:internet_information_services` |
   | `mysql` | `oracle:mysql` |
   | `php` | `php:php` |
   | `openssl` | `openssl:openssl` |
   | `tomcat` | `apache:tomcat` |
   | `exchange` | `microsoft:exchange_server` |
   | `postfix` | `postfix:postfix` |
   | `vsftpd` | `beasts:vsftpd` |
   | `proftpd` | `proftpd:proftpd` |
   | `samba` | `samba:samba` |

   Un alias che mappa su più CPE (come `nginx`) **non** è considerato ambiguo: la
   ricerca copre tutte le coppie mappate.

2. **Match esatto** sul prodotto normalizzato (minuscolo, spazi e trattini →
   underscore: `"Apache HTTP Server"` → `apache_http_server`).

3. **Ricerca `LIKE`** su `vendor:product`: ogni parola del termine deve comparire,
   così `"apache http"` trova `apache:http_server`.

I candidati sono ordinati per numero di CVE associate. **Se il termine resta ambiguo,
`search` non indovina**: stampa i candidati con il conteggio ed esce con codice 2,
chiedendo di rilanciare con `--vendor` o `--cpe`.

```
$ nvdlocal search --product apache --version 2.4.52
il termine 'apache' corrisponde a 2 prodotti distinti: rilancia specificando --vendor oppure --cpe.
┏━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━┓
┃ Vendor ┃ Product     ┃ CVE ┃
┡━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━┩
│ apache │ http_server │   2 │
│ apache │ tomcat      │   1 │
└────────┴─────────────┴─────┘
```

---

## Exit code

Pensati per l'uso in pipeline:

| Comando | 0 | 1 | 2 |
|---|---|---|---|
| `search` | nessuna CVE trovata, o nessuna con severità ≥ HIGH | almeno una CVE **HIGH o CRITICAL** | errore (DB assente, prodotto ambiguo o sconosciuto, argomenti mancanti) |
| `batch` | nessuna CVE ≥ HIGH | almeno una CVE ≥ HIGH | errore (inventario assente o malformato) |
| `sync`, `resolve`, `show`, `stats` | ok | — | errore (rete, DB assente, CVE non trovata) |

```bash
# Gate in CI/CD
if ! nvdlocal search -p httpd -V "$VERSIONE" --min-severity HIGH --only-kev; then
    echo "Trovate vulnerabilità sfruttate attivamente" >&2
    exit 1
fi
```

---

## Architettura

```
nvdlocal/
  cli.py        comandi typer, exit code, lettura inventario
  config.py     path del DB, API key da env/.env, costanti di rete, logging
  db.py         schema, connessione, migrazioni, parsing NVD, upsert idempotente
  sync.py       download full + incrementale, rate limiting, retry, checkpoint
  cpe.py        parser CPE 2.3 con escaping, normalizzazione nomi, alias
  versions.py   comparatore di versioni "naturale"
  matcher.py    motore di matching software+versione -> CVE, batch inventario
  enrich.py     CISA KEV + EPSS
  output.py     rendering table/json/csv/xlsx
  api.py        FastAPI opzionale
```

Principi trasversali: type hints ovunque, docstring sulle funzioni pubbliche,
`logging` per la diagnostica e `rich` **solo** nel layer di output, nessun `print`
sparso, SQL diretto sempre parametrizzato, errori applicativi con messaggio
esplicito (DB assente → invito a lanciare `sync --full`; rete assente → errore
leggibile, mai uno stacktrace).

### Il comparatore di versioni

Le versioni nei CPE non sono PEP 440, quindi `packaging.version` da solo non basta.
`versions.compare(a, b)` implementa un confronto naturale:

- tokenizzazione in sequenze alternate di cifre e lettere: `8.5p1` → `[8, 5, 'p', 1]`;
- confronto numerico fra numeri, lessicografico fra stringhe;
- a parità di posizione un **numero è minore di una stringa**: `1.2.3a > 1.2.3`,
  `8.5p1 > 8.5`;
- padding con zeri: `1.0 == 1.0.0`;
- i marcatori di pre-release (`alpha`, `beta`, `rc`, `pre`, `dev`, `snapshot`) sono
  minori di tutto il resto: `1.0-rc1 < 1.0`;
- i valori speciali CPE `*` (ANY) e `-` (NA) non sono versioni: `compare` solleva
  `ValueError` e il matcher li intercetta prima.

Casi coperti dai test: `2.4.52 < 2.4.53`, `1.0 == 1.0.0`, `8.5p1 > 8.5`,
`1.0-rc1 < 1.0`, `2.4.9 < 2.4.10`, `1.2.3a > 1.2.3`, `9.0 > 10.0` è falso,
`0.9.8zh > 0.9.8h`.

### Il parser CPE

`cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other`
con **escaping via backslash**: `cpe:2.3:a:apache:http_server:2.4.49\:beta:...` ha
versione `2.4.49:beta`, non `2.4.49`. Lo split è consapevole dell'escaping, non è un
`split(":")`.

---

## Schema del database

```sql
cve(cve_id PK, published, last_modified, vuln_status, description,
    cvss_version, cvss_score, cvss_severity, cvss_vector, cwe,
    references_json, raw_json)

cpe_match(id PK, cve_id FK -> cve ON DELETE CASCADE,
          config_index, node_index, config_operator, node_operator, negate,
          vulnerable, criteria,
          part, vendor, product, version, update_field, edition,
          sw_edition, target_sw, target_hw, other,
          version_start_including, version_start_excluding,
          version_end_including, version_end_excluding)

kev(cve_id PK, date_added, ransomware, due_date)
epss(cve_id PK, score, percentile, updated)
meta(key PK, value)
```

Indici su `cpe_match(vendor, product)`, `cpe_match(product)`, `cpe_match(cve_id)` e
`cve(cvss_severity)`.

Note:

- `cvss_*` contiene **la metrica migliore disponibile**, con priorità
  **v4.0 > v3.1 > v3.0 > v2**, preferendo le voci `type: "Primary"`.
- `configurations` è una **lista** di configurazioni, ognuna con una lista di `nodes`,
  ognuno con una lista di `cpeMatch`; i vincoli di versione stanno a livello di
  `cpeMatch`, non dentro la stringa CPE. `cpe_match` è la versione appiattita di
  questa struttura, con gli indici che permettono di ricostruire la gerarchia.
- **Upsert idempotente**: all'aggiornamento di una CVE tutte le sue righe `cpe_match`
  vengono cancellate e reinserite, perché le configurazioni cambiano nel tempo.
  Sincronizzare due volte la stessa CVE non duplica nulla (c'è un test apposta).
- Scritture in transazioni a blocchi di 2000 record, `PRAGMA journal_mode=WAL`.

---

## Test

```bash
pytest              # 185 test, ~1,3 s
```

I test girano **completamente offline**: nessuna chiamata di rete. Le fixture in
`tests/fixtures/` sono risposte NVD 2.0 reali ma ridotte (vedi
[`tests/fixtures/README.md`](tests/fixtures/README.md)) e coprono versione esatta,
range `versionEndExcluding`, configurazione `AND`, CVE senza `configurations` e CPE
senza versione. La sincronizzazione è testata con `httpx.MockTransport`.

| File | Copertura |
|---|---|
| `test_versions.py` | comparatore: tutti i casi richiesti, pre-release, padding, valori speciali, ordinamento di una release line reale |
| `test_cpe.py` | parser con escaping (`\:`, `\\`), CPE troncati e invalidi, normalizzazione, alias |
| `test_matcher.py` | tutti e sei i casi della logica di matching, i quattro vincoli di range, filtri, KEV/EPSS, ambiguità, batch |
| `test_db.py` | upsert idempotente, sostituzione delle configurazioni obsolete, priorità delle metriche CVSS, CVE senza `configurations` |
| `test_sync.py` | paginazione, `--max-pages`, checkpoint/resume, retry su 403/429/503 e timeout, finestre da 120 giorni |
| `test_cli.py` | exit code, formati `table`/`json`/`csv`, `batch` xlsx e csv, messaggi d'errore |

---

## Scelte implementative e limiti noti

**Tokenizzazione delle versioni di distribuzione.** `2.4.53-1ubuntu1` viene
tokenizzato in `[2, 4, 53, 1, 'ubuntu', 1]`, mantenendo il numero di revisione della
distribuzione. Così `2.4.53-1ubuntu1 > 2.4.53` e `2.4.52-1ubuntu4.3 >
2.4.52-1ubuntu4.2`, che è l'ordinamento corretto; scartare quel token renderebbe
indistinguibili due revisioni diverse dello stesso pacchetto.

**Backporting delle patch.** Il limite più importante in assoluto: i CPE descrivono
le versioni *upstream*. Su Debian/Ubuntu/RHEL una versione formalmente vulnerabile
può avere la patch già applicata dal manutentore. `nvdlocal` non può saperlo e
segnalerà comunque la CVE. Per gli host con pacchetti di distribuzione, incrocia i
risultati con gli advisory del vendor.

**Righe `vulnerable: false`.** Scartate dal matching (vedi sopra). Restano nel
database e si vedono in `show`, perché servono a ricostruire le condizioni dei match
`conditional`.

**Valore CPE `-` (NA) nella versione.** Se accompagnato da vincoli di range, i
vincoli vengono valutati; senza vincoli la riga non esprime alcuna versione e non
produce match.

**`sqlite3` e non un ORM.** Query dirette e parametrizzate: su ~3 milioni di righe
`cpe_match` la ricerca resta nell'ordine dei millisecondi grazie all'indice su
`(vendor, product)`.

**Modelli.** `pydantic` valida i modelli di dominio (`MatchResult`, `SearchFilters`,
`InventoryRow`, gli schemi dell'API). La classe `CPE23` è invece una dataclass
slotted: sta sul percorso caldo della sync (milioni di `cpeMatch` da parsare) e il
costo di validazione non sarebbe giustificato.

**Fuso orario.** Le date sono trattate in UTC. `lastModStartDate`/`lastModEndDate`
sono formattate come `2026-01-15T00:00:00.000`, con partenza dall'ultima sync meno
un'ora per non perdere modifiche a cavallo della finestra.
