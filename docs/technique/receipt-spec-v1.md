---
title: Tessaliq Receipt JWT — spécification v1
status: spec en cours de stabilisation
version: v1.0-draft (2026-04-20)
audience: dev tiers, auditeurs, DPO, régulateurs
issue: #135
related:
  - docs/strategie/refinement-2026-04-20-focus-av-moats.md §2 (R3a)
  - packages/api/src/lib/receipt-signer.ts
  - packages/api/src/routes/public.ts
---

# Tessaliq Receipt JWT — spécification v1

## Propos

Ce document spécifie le format et les invariants du **receipt JWT** émis par Tessaliq à l'issue de chaque vérification d'un credential EUDI (mdoc ISO 18013-5 ou SD-JWT-VC). Le receipt est conçu pour être **vérifié par un tiers indépendant** (auditeur, régulateur, ou RP) **sans coordination avec Tessaliq** — la vérification cryptographique repose uniquement sur la clé publique exposée via le endpoint JWKS standard (public, non authentifié, cacheable).

La spec documente le comportement **actuel** du code (packages/api/src/lib/receipt-signer.ts) au 2026-04-20. Les limitations connues sont listées en §9. Une lib tierce `@tessaliq/receipt-verifier` (MIT) est en cours de préparation (cf. issue #135) pour encapsuler la procédure de vérification.

> **Audience** : ce document est technique. Pour une présentation grand public des garanties apportées par le receipt, voir `/receipt` (à venir) sur le site Tessaliq.

---

## 1. Vue d'ensemble

Un receipt Tessaliq est un **JSON Web Token signé (RFC 7519)** au format JWS compact à 3 segments :

```
<header-base64url>.<payload-base64url>.<signature-base64url>
```

- **Algorithme de signature** : ES256 (ECDSA over P-256, RFC 7518 §3.4)
- **Content type** : `application/tessaliq-receipt+jwt` (indiqué par le claim header `typ`)
- **Key identifier** : `tessaliq-receipt-v1` (claim header `kid`, constant en v1)
- **Durée de vie** : **permanent** (aucun claim `exp` en v1 — voir §9.2)

Le receipt est **émis à la demande** après qu'une session de vérification ait atteint l'état terminal `verified` ou `failed`, via l'endpoint :

```
GET /v1/sessions/:session_id/receipt
Authorization: Bearer <organization_api_key>
```

Une fois émis, le receipt est **immuable** et stocké en base par son empreinte SHA-256 (`receipt_fingerprint`). Toute demande ultérieure sur la même session renvoie le même JWT (idempotence).

---

## 2. Format du header JWT

Le header protégé est un objet JSON à 3 champs :

```json
{
  "alg": "ES256",
  "kid": "tessaliq-receipt-v1",
  "typ": "tessaliq-receipt+jwt"
}
```

| Champ | Type | Obligatoire | Valeur | Sémantique |
|---|---|---|---|---|
| `alg` | string | ✅ | `ES256` | Algorithme de signature JWS (invariant en v1) |
| `kid` | string | ✅ | `tessaliq-receipt-v1` | Key ID correspondant à la clé publique dans le JWKS Tessaliq (invariant en v1) |
| `typ` | string | ✅ | `tessaliq-receipt+jwt` | Type MIME distinguant ce JWT des autres tokens Tessaliq (access tokens, 2FA tokens, etc.) |

**Note implémenteur** : un vérifieur tiers DOIT rejeter tout receipt dont `alg` ≠ `ES256` (prévention attaque de downgrade, notamment `alg: none`).

---

## 3. Format du payload

Le payload est un objet JSON composé de **claims standards RFC 7519** et de **claims Tessaliq-spécifiques**.

### 3.1 Claims standards

| Champ | Type | Obligatoire | Source / Valeur | Exemple |
|---|---|---|---|---|
| `iss` | string (URI) | ✅ | Identifiant de l'émetteur, constant en prod : `https://api.tessaliq.com` | `https://api.tessaliq.com` |
| `iat` | integer (Unix epoch seconds) | ✅ | Timestamp de signature du receipt | `1713607335` |
| `jti` | string (UUID) | ✅ | = `session_id` (identique pour idempotence et audit) | `550e8400-e29b-41d4-a716-446655440000` |
| `exp` | — | ❌ | **Absent en v1** — le receipt ne porte pas de date d'expiration (voir §9.2) | — |
| `nbf` | — | ❌ | **Absent en v1** | — |

### 3.2 Claims Tessaliq-spécifiques

| Champ | Type | Obligatoire | Description |
|---|---|---|---|
| `session_id` | UUID string | ✅ | Identifiant unique de la session de vérification (duplique `jti` par lisibilité) |
| `organization_id` | UUID string | ✅ | Identifiant de l'organisation Tessaliq cliente ayant initié la session |
| `verification` | object | ✅ | Métadonnées de la vérification (cf. §3.3) |
| `proof` | object \| null | ✅ | Preuve ZK associée si applicable, sinon `null` (cf. §3.4) |
| `dpv` | object (JSON-LD) | ❌ | Déclaration DPV du traitement (cf. §3.5) — présent sur tous les receipts émis depuis 2026-04-19 |

### 3.3 Objet `verification`

| Champ | Type | Obligatoire | Valeurs possibles |
|---|---|---|---|
| `policy` | string | ✅ | Nom canonique de la policy appliquée (ex. `age_18_plus`, `age_21_plus`) |
| `policy_version` | integer | ✅ | Version numérique de la policy (1, 2, …) |
| `result` | boolean | ✅ | Résultat final : `true` si la vérification a validé la policy, `false` sinon |
| `state` | enum string | ✅ | `verified` \| `failed` (état terminal de la session) |
| `created_at` | ISO 8601 string | ✅ | Timestamp de création de la session de vérification |
| `completed_at` | ISO 8601 string \| null | ✅ | Timestamp d'atteinte de l'état terminal ; peut être `null` si échec sans complétion |
| `assurance_level` | enum string | ✅ | `low` \| `substantial` \| `high` \| `unknown` — Level of Assurance eIDAS du PID sous-jacent. **Défaut `unknown` en v1** (cf. §9.3) |

### 3.4 Objet `proof` (présent uniquement pour les vérifications ZK)

Pour les policies qui s'appuient sur un circuit zero-knowledge Noir (path alpha opt-in en v1), l'objet `proof` contient :

| Champ | Type | Obligatoire | Description |
|---|---|---|---|
| `circuit_id` | string | ✅ | Identifiant du circuit (ex. `age_range_v1`) |
| `circuit_version` | string | ✅ | Version du compilateur Noir utilisé (ex. `0.36.0`) |
| `proof_hash` | string (64 hex chars) | ✅ | SHA-256 du blob de preuve, en hexadécimal lowercase |
| `verified_at` | ISO 8601 string | ✅ | Timestamp de vérification de la preuve côté Tessaliq |

Pour les policies mdoc attribute-check (voie de production Tessaliq — `av_age_*`), `proof` vaut `null`.

### 3.5 Objet `dpv` (facultatif en schéma, systématique en pratique depuis 2026-04-19)

JSON-LD selon le vocabulaire [Data Privacy Vocabulary v2](https://w3c.github.io/dpv/dpv/). Contient notamment :

- `@context` : URIs des contextes DPV, DPV-GDPR, XSD
- `@type` : `dpv:PersonalDataHandling`
- `dpv:hasPurpose` : URI du but du traitement (ex. `https://w3id.org/dpv#AgeVerification`)
- `dpv:hasLegalBasis` : URI de la base légale RGPD
- `dpv:hasDataRetentionPeriod` : durée ISO 8601 (par défaut `P0D` — zéro rétention)
- `dpv:hasDataController` : URI du responsable de traitement
- `dpv:hasProcessingContext` : `eu.europa.ec.eidas2.verifier`

**Statut** : le champ est marqué **optionnel dans le schéma TypeScript** (`dpv?: DpvJsonLd` dans `ReceiptPayload`) **pour compatibilité arrière** — les receipts émis avant le **rollout du 2026-04-19** ne le contiennent pas et restent cryptographiquement valides. Tous les nouveaux receipts émis depuis cette date l'embarquent systématiquement. Un vérifieur tiers DOIT donc traiter `dpv` comme optionnel et ne pas échouer s'il est absent.

Implémentation : `packages/api/src/lib/dpv.ts`.

---

## 4. Signature

### 4.1 Algorithme

- **Schéma** : ECDSA (FIPS 186-4) sur la courbe **P-256** (aka `secp256r1`, `prime256v1`, NIST Prime Curve 256-bit)
- **Hash** : SHA-256
- **Encodage signature** : concaténation `r || s` (64 octets bruts) encodée en base64url dans le segment signature du JWT, conforme RFC 7515 §3.4
- **Identifiant JWS** : `ES256` (RFC 7518 §3.1 / §3.4)

Niveau de sécurité : ~128 bits symétriques.

### 4.2 Clé privée (Tessaliq)

- Stockage : variable d'environnement `RECEIPT_SIGNING_KEY` (JWK JSON complète, encodée en base64url)
- Provisioning prod : Fly.io secrets
- Génération : `scripts/generate-receipt-key.sh` via `jose.generateKeyPair('ES256')`

> **Invariant opérationnel** : en environnement de production, la variable DOIT être définie. Si elle est absente, une clé éphémère est générée au démarrage et **les receipts ne survivent pas aux redémarrages** — cette configuration est à usage de développement uniquement.

### 4.3 Clé publique (JWKS endpoint)

La clé publique correspondante est exposée au endpoint standard :

```
GET https://api.tessaliq.com/.well-known/jwks.json
```

Réponse (exemple) :

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "kid": "tessaliq-receipt-v1",
      "use": "sig",
      "alg": "ES256"
    }
  ]
}
```

- **Cache** : `Cache-Control: public, max-age=3600` (1 heure côté intermédiaires)
- **Authentification** : aucune (endpoint public)
- **Versionning** : en cas de rotation future, un nouveau `kid` sera publié et les deux clés coexisteront le temps de la bascule (pas de bascule en v1)

---

## 5. Exemples

### 5.1 Payload déchiffré (cas nominal mdoc AV, pas de ZK)

```json
{
  "iss": "https://api.tessaliq.com",
  "iat": 1713607335,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "organization_id": "7f3d2e1a-8b4c-4d5e-9f6a-1b2c3d4e5f6a",
  "verification": {
    "policy": "av_age_18_plus",
    "policy_version": 1,
    "result": true,
    "state": "verified",
    "created_at": "2026-04-20T12:00:00.000Z",
    "completed_at": "2026-04-20T12:00:02.145Z",
    "assurance_level": "unknown"
  },
  "proof": null,
  "dpv": {
    "@context": ["https://w3id.org/dpv", "https://w3id.org/dpv/dpv-gdpr", "http://www.w3.org/2001/XMLSchema#"],
    "@type": "dpv:PersonalDataHandling",
    "dpv:hasPurpose": "https://w3id.org/dpv#AgeVerification",
    "dpv:hasLegalBasis": "https://w3id.org/dpv/dpv-gdpr#LegalObligation",
    "dpv:hasDataRetentionPeriod": "P0D",
    "dpv:hasProcessingContext": "eu.europa.ec.eidas2.verifier"
  }
}
```

### 5.2 Payload déchiffré (cas ZK alpha, policy `age_18_plus`)

```json
{
  "iss": "https://api.tessaliq.com",
  "iat": 1713607335,
  "jti": "c9d8e7f6-b5a4-3210-fedc-ba9876543210",
  "session_id": "c9d8e7f6-b5a4-3210-fedc-ba9876543210",
  "organization_id": "7f3d2e1a-8b4c-4d5e-9f6a-1b2c3d4e5f6a",
  "verification": {
    "policy": "age_18_plus",
    "policy_version": 1,
    "result": true,
    "state": "verified",
    "created_at": "2026-04-20T12:00:00.000Z",
    "completed_at": "2026-04-20T12:00:01.820Z",
    "assurance_level": "unknown"
  },
  "proof": {
    "circuit_id": "age_range_v1",
    "circuit_version": "0.36.0",
    "proof_hash": "a3f0c8e1b4d7296f5a8c2e1b0f9d7e6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e",
    "verified_at": "2026-04-20T12:00:01.820Z"
  }
}
```

### 5.3 Payload déchiffré (cas `failed` — credential invalide)

Une vérification peut aboutir à `state: "failed"` pour plusieurs raisons : signature invalide, trust chain non reconnue, policy non satisfaite (ex. âge inférieur au seuil), credential expiré, nonce rejoué, etc. Le receipt est émis avec la même structure et reste cryptographiquement valide — seuls `verification.state`, `verification.result` et éventuellement `completed_at` changent.

```json
{
  "iss": "https://api.tessaliq.com",
  "iat": 1713612000,
  "jti": "3b2c1d0e-9f8a-7b6c-5d4e-1f2a3b4c5d6e",
  "session_id": "3b2c1d0e-9f8a-7b6c-5d4e-1f2a3b4c5d6e",
  "organization_id": "7f3d2e1a-8b4c-4d5e-9f6a-1b2c3d4e5f6a",
  "verification": {
    "policy": "av_age_18_plus",
    "policy_version": 1,
    "result": false,
    "state": "failed",
    "created_at": "2026-04-20T13:20:00.000Z",
    "completed_at": "2026-04-20T13:20:03.412Z",
    "assurance_level": "unknown"
  },
  "proof": null
}
```

**Note** : le receipt `failed` est un artefact d'audit à part entière, au même titre qu'un receipt `verified`. Il prouve que Tessaliq a bien été sollicité et a refusé la présentation — utile pour une RP qui doit démontrer qu'elle a tenté la vérification. Il ne divulgue pas la raison métier de l'échec (ce choix protège la vie privée du wallet user qui ne satisfait pas la policy).

### 5.4 Receipt complet (format JWS compact, exemple illustratif)

```
eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3NhbGlxLXJlY2VpcHQtdjEiLCJ0eXAiOiJ0ZXNzYWxpcS1yZWNlaXB0K2p3dCJ9
.eyJpc3MiOiJodHRwczovL2FwaS50ZXNzYWxpcS5jb20iLCJpYXQiOjE3MTM2MDczMzUs[...tronqué...]
.MEUCIQDyKk9f3Zs2R8qHg[...signature ES256, ~86 caractères base64url...]
```

Un exemple non-tronqué issu d'un receipt de staging sera fourni dans les matériaux qui accompagneront la lib `@tessaliq/receipt-verifier` (cf. issue #135).

---

## 6. Vérification par un tiers (procédure manuelle)

Un auditeur, un RP, un régulateur ou tout tiers peut vérifier un receipt Tessaliq sans coordination avec Tessaliq (pas de ticket, pas d'appel authentifié — juste le JWKS public), en suivant la procédure standard JWS :

### 6.1 Étapes

1. **Parser le JWT** en 3 segments `<header>.<payload>.<signature>` (split sur `.`).
2. **Décoder le header** (base64url → JSON) et **contrôler** :
   - `alg === "ES256"` (rejeter tout autre algorithme, notamment `none`)
   - `kid === "tessaliq-receipt-v1"` (v1)
   - `typ === "tessaliq-receipt+jwt"`
3. **Récupérer la clé publique Tessaliq** depuis `https://api.tessaliq.com/.well-known/jwks.json` et sélectionner la JWK dont `kid` correspond au header.
4. **Vérifier la signature** avec la clé publique P-256 sur les bytes `<header>.<payload>` (segment non-signature), algorithme ECDSA-SHA256. Toute bibliothèque JWS standard (RFC 7515) le fait — voir §6.2.
5. **Décoder le payload** (base64url → JSON) et **contrôler les invariants** :
   - `iss === "https://api.tessaliq.com"` en prod
   - `jti === session_id` (invariant structurel)
   - `verification.state ∈ {"verified", "failed"}`
   - Autres contrôles métier selon contexte (policy attendue, organization_id, date range de `iat`, etc.)

### 6.2 Exemple vérificateur minimal (Node.js, librairie `jose`)

```ts
import { jwtVerify, createRemoteJWKSet } from 'jose';

const JWKS = createRemoteJWKSet(
  new URL('https://api.tessaliq.com/.well-known/jwks.json')
);

async function verifyTessaliqReceipt(jwt: string) {
  const { payload, protectedHeader } = await jwtVerify(jwt, JWKS, {
    issuer: 'https://api.tessaliq.com',
    algorithms: ['ES256'],
    typ: 'tessaliq-receipt+jwt',
  });
  return { payload, protectedHeader };
}
```

Toute erreur de signature, d'algorithme ou d'issuer lèvera une exception. La fonction retourne le payload typé en cas de succès.

### 6.3 Librairie `@tessaliq/receipt-verifier` (à venir)

Une lib MIT encapsulant cette procédure avec types TypeScript, CLI et exemples d'intégration est publiée dans `Tessaliq/tessaliq-open/packages/receipt-verifier` (v0.1.0-draft au 2026-04-20). Elle lit par défaut le JWKS public, et accepte un JWKS pré-fetché via l'option `jwks` pour une vérification totalement air-gapped.

---

## 7. Diagramme de séquence

```
 RP (client)      Tessaliq API         Wallet user           Auditeur tiers
     │                │                    │                        │
     │  POST /sessions│                    │                        │
     │───────────────>│                    │                        │
     │  session_id    │                    │                        │
     │<───────────────│                    │                        │
     │                                     │                        │
     │   redirect_url ───────────────────> │                        │
     │                                     │                        │
     │                │  OID4VP response   │                        │
     │                │<────────────────── │                        │
     │                │                                             │
     │                │ verify credential (mdoc / SD-JWT / ZK)      │
     │                │ update session → "verified"                 │
     │                │                                             │
     │  GET /sessions/:id/receipt                                   │
     │───────────────>│                                             │
     │  JWT receipt   │                                             │
     │<───────────────│                                             │
     │                                                              │
     │   stocke receipt côté RP                                     │
     │                                                              │
     │   transmet JWT à l'auditeur ───────────────────────────────> │
     │                                                              │
     │                                     GET /.well-known/jwks.json
     │                                     <──────────────────────  │
     │                                     { keys: [...] }          │
     │                                                              │
     │                                     vérifie signature ES256  │
     │                                     avec clé publique        │
     │                                     (aucun appel API Tessaliq)
     │                                                              │
     │                                     ✓ authentique / ✗ falsifié
```

---

## 8. Garanties apportées par le receipt

### 8.1 Garanties cryptographiques (vérifiables par un tiers)

- Le JWT a été **signé par la clé privée correspondant à la JWK `tessaliq-receipt-v1`** publiée par Tessaliq au moment de la signature.
- Les claims (session_id, policy, result, timestamps, proof hash, dpv) **n'ont pas été modifiés** depuis la signature.
- L'intégrité est garantie par ECDSA P-256 (~128 bits de sécurité symétrique).

### 8.2 Attestations portées par le receipt (dépendent de la véracité de Tessaliq)

Au-delà de l'intégrité cryptographique, le receipt **atteste** (au sens : Tessaliq déclare, et signe cette déclaration) que :

- Tessaliq a appliqué la policy `policy` (version `policy_version`) à une présentation de credential EUDI, et a obtenu le résultat `result` à l'instant `completed_at`.
- Le cas échéant, une preuve ZK identifiée par `proof.circuit_id` et `proof.circuit_version` a été vérifiée par Tessaliq, dont l'empreinte SHA-256 vaut `proof.proof_hash`.
- Le traitement des données personnelles s'est effectué conformément à la déclaration DPV portée par le claim `dpv` (purpose, legal basis, retention period).

Ces attestations sont **cryptographiquement liées à Tessaliq** (non répudiables sous hypothèse que la clé privée n'a pas été compromise). Elles **ne remplacent pas un audit indépendant** de la logique de vérification — la conformité de Tessaliq à ses propres déclarations se démontre par la publication des plans OIDF et du code open-core, pas par le receipt seul.

### 8.3 Ce que le receipt ne prouve pas (en v1)

- Il ne prouve pas que la session existe dans la base Tessaliq (pas d'endpoint public de lookup — voir §9.5).
- Il ne prouve pas l'identité du wallet user, **par design** (double anonymat ARCOM).
- Il ne prouve pas que la clé privée Tessaliq n'a pas été compromise ultérieurement (en cas de compromission détectée, la clé est rotée et le `kid` changé — voir §9.1).
- Il ne prouve pas, à lui seul, que la logique interne de Tessaliq applique correctement la policy déclarée — cette vérification relève de l'audit du verifier (plans OIDF publics, code source partiellement ouvert, position paper ENISA).

### 8.4 Ce que le receipt garantit opérationnellement à Tessaliq

- Rejeu impossible sans accès à la clé privée.
- Modification impossible sans re-signature, détectable immédiatement par tout vérifieur conforme.
- Traçabilité : chaque receipt est indexé par son empreinte SHA-256 (`receipt_fingerprint`) côté base.

---

## 9. Limitations connues en v1

### 9.1 Pas de révocation

Aucun mécanisme de révocation n'est implémenté en v1. Un receipt émis reste valide tant que la clé publique correspondante reste accessible via le JWKS endpoint. En cas de compromission suspectée de la clé privée, la procédure prévue est la rotation de `kid` (bascule vers `tessaliq-receipt-v2`) et la publication d'une note de sécurité documentant la période affectée.

### 9.2 Pas de claim `exp`

Le receipt n'a pas de date d'expiration en v1 — il est conçu comme un artefact d'audit permanent. L'absence de `exp` signifie que la vérification ne doit PAS échouer sur une expiration automatique. Si un tiers a besoin d'une durée de validité pour un usage spécifique (ex. preuve d'âge valable 24h pour un flow de paiement), c'est à la logique métier tierce de l'imposer en contrôlant `iat` vs. heure courante.

### 9.3 `assurance_level` vaut souvent `unknown`

Le Level of Assurance eIDAS du PID sous-jacent n'est pas systématiquement propagé depuis le wallet vers Tessaliq en v1 (voir issue #79 historique). La valeur par défaut est `unknown`. Elle sera remplacée par la valeur réelle (`low`, `substantial`, `high`) quand le wallet l'expose côté OID4VP. Ne pas traiter `unknown` comme équivalent à `low`.

### 9.4 Pas de librairie tierce packagée

La vérification côté tiers est possible manuellement (cf. §6) mais aucune librairie `@tessaliq/receipt-verifier` n'est encore publiée. Elle est en préparation (cf. issue #135). En attendant, les tiers peuvent utiliser toute lib JWS conforme RFC 7515 (ex. `jose` en Node.js, `PyJWT` + `cryptography` en Python, `jose4j` en Java, `golang-jwt/jwt` en Go).

### 9.5 Endpoint existence check non public

Un endpoint `POST /v1/receipts/verify` côté Tessaliq permet de valider qu'un receipt correspond bien à une session existante en base. Cet endpoint n'est accessible qu'en authentifié (organisation ayant émis le receipt). Il n'est pas destiné à un auditeur tiers — son rôle est complémentaire, pas indispensable.

---

## 10. Roadmap au-delà de v1

Éléments envisagés (non engagés) pour versions futures, à discuter avec la communauté :

- **v1.1** : publication `@tessaliq/receipt-verifier` (MIT) avec CLI + SDK TypeScript/Node + browser
- **v1.2** : endpoint public de lookup par fingerprint pour confirmer l'existence DB (anonyme, rate-limited) — optionnel, le receipt reste cryptographiquement vérifiable sans
- **v1.3** : propagation `assurance_level` réelle quand le wallet l'expose de bout en bout
- **v2** : rotation de `kid` quand nécessaire (compromission suspectée, changement d'algo — ex. ML-DSA post-quantique)
- **v2+** : schéma de révocation si un cas d'usage le justifie (ex. receipts signés avant une vulnérabilité détectée côté circuit ZK)

Les évolutions suivront SemVer côté schéma : un ajout de claim rétrocompatible = v1.x, un changement non-rétrocompatible = v2.

---

## 11. Références

- **RFC 7515** — JSON Web Signature (JWS)
- **RFC 7517** — JSON Web Key (JWK) / JWKS
- **RFC 7518** — JSON Web Algorithms (JWA) — définit `ES256`
- **RFC 7519** — JSON Web Token (JWT)
- **RFC 8037** — JSON Web Signature Unencoded Payload Option
- **FIPS 186-4** — Digital Signature Standard (ECDSA)
- **DPV v2** — [Data Privacy Vocabulary](https://w3c.github.io/dpv/dpv/) (W3C Draft)

---

## 12. Historique

- **v1.0-draft — 2026-04-20** : rédaction initiale de la spec sur base du code `packages/api/src/lib/receipt-signer.ts` au commit `16a6cc18`. Issue de tracking : #135. Première version destinée à une publication publique — pas encore gelée, en attente de revue Olivier + éventuelle revue tiers (ex. OWF, DIF).

## À vérifier avant publication externe

- [x] ~~Valider que tous les claims obligatoires listés sont bien présents dans 100% des receipts actuels~~ — confirmé via relecture `packages/api/src/lib/receipt-signer.ts` (setIssuer/setIssuedAt/setJti systématiques, ReceiptPayload TypeScript force session_id/organization_id/verification/proof)
- [x] ~~Vérifier que `dpv` est effectivement optionnel (backward-compat)~~ — confirmé : `dpv?` dans `ReceiptPayload`, rollout systématique depuis 2026-04-19, ancienne data conservée sans dpv (cf. §3.5)
- [x] ~~Wording ENISA-compatible pour §8 "garanties"~~ — §8 découpé en 4 sous-sections : garanties cryptographiques / attestations Tessaliq / limites / garanties opérationnelles. Distinction claire entre ce qui est prouvable par tout tiers et ce qui dépend de la confiance en Tessaliq
- [x] ~~Ajouter un exemple `failed`~~ — §5.3 ajouté
- [ ] **Reste à faire** : relire §6.2 exemple Node.js en conditions réelles (extraire un receipt réel de staging + runner l'exemple) — dépend de l'accès staging
- [ ] **Reste à faire** : générer un JWT non-tronqué réel pour §5.4 à partir d'un receipt de staging — dépend idem
- [ ] **Reste à faire** : avant publication externe, passer un œil tiers sur la spec (OWF Slack, DIF, ou un implémenteur verifier EUDI connu) pour retour cohérence et absence d'overclaim
