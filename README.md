# StarkCore — Validador MTE v1.2

Verificador *fail-closed* de la identidad operacional de un sistema
(STARKCORE-MORPH-001). El veredicto es función de la **trayectoria** (la historia
firmada), nunca del snapshot final.

```
POST /api/validate
```

## Veredictos

| Veredicto | Significado | Acción del Enforcer |
|---|---|---|
| `ACCEPT` | Cadena criptográficamente consistente, invariantes conservados, testigo anclado. | `NONE` |
| `REJECT` | Evidencia positiva de violación (invariante en FAIL, divergencia del testigo, cadena rota). | `ISOLATE` / `BYZANTINE` |
| `BLOCK` | Evidencia insuficiente. El validador no puede afirmar que el sistema sea seguro, así que no lo afirma. | `FREEZE` |

`BLOCK` no es un modo de fallo: es la postura por defecto.

## Niveles de evidencia (`Theta_ev`, Cap 9.2)

| Nivel | Testigos divergentes | Acción |
|---|---|---|
| 0 | lote incompleto (`events_lost > 0`) o sin `3f+1` nodos | `FREEZE` |
| 1 | 1 testigo | `OBSERVE` |
| 2 | `f+1` | `BLOCK` |
| 3 | `2f+1` | `ISOLATE` |
| 4 | prueba criptográfica de reescritura | `BYZANTINE` (expulsión) |

Con `N = 7` y `f = 2` se toleran dos bizantinos: `N >= 3f+1`.
Expulsión irreversible solo con `2f+1` o más.

## Invariantes

- **I1** estructura, **I2** autorización, **I3** relaciones, **I4** registro.
  Se aceptan las formas planas (`I1: true`) y la del JSON Schema (`I1_structure: "PASS"`).
  Un `FAIL` sin autorización explícita produce `REJECT` (nivel 3).
  Un invariante ausente no se asume conservado: se emite un *warning*.
- **I5** consistencia de enjambre: comparación **exacta** de hashes, nunca por resta
  numérica (Cap 10.2). `1` coincidencia, `0` contradicción verificable, `null` sin evidencia.
- **I6** causalidad por **hash**, no por reloj (Cap 10 V3). El `timestamp_utc` es solo corroboración.
- **Contador de secuencia monotónico** (Cap 10 V1): el árbol de Merkle prueba *qué* se
  capturó, no que no falte nada. La completitud la sostienen el contador `seq` (estrictamente
  creciente, sin huecos ni repeticiones) y `events_lost`. Un `seq` no monotónico o un
  `events_lost` negativo no son evidencia de manipulación, sino de lote incompleto: `BLOCK`/`FREEZE`.

## Correcciones aplicadas al borrador del Cap 10

El borrador v1.2 tenía cinco defectos que se corrigieron aquí:

1. **El `trajectory_hash` de la respuesta era `SHA256("")`** — una constante, no un hash
   de la trayectoria. Ahora es el compromiso real del último bloque.
2. **La cadena no comprometía el `transformation_hash`.** `H_k` era
   `SHA256(prev || tid || ts || sig)`, así que el *payload* de un bloque pasado podía
   reescribirse sin romper la cadena — la propiedad de "no borrado cuántico" (Cap 4.4)
   no se sostenía. Ahora `H_k = SHA256(prev || tid || ts || sig || thash)`.
3. **I5 se comparaba por resta numérica** (`anchor != t.transformation_hash` con
   conversiones implícitas). Ahora la comparación es exacta y tipada.
4. **I6 se evaluaba después de los invariantes y devolvía veredictos mezclados**
   (`BOT` para cadena rota, `REJECT` para divergencia). Ahora la cadena rota es
   evidencia positiva: `REJECT` nivel 4.
5. **El umbral bizantino `N >= 3f+1` no se verificaba.** Un enjambre de 5 nodos con
   `f = 2` no puede distinguir un testigo bizantino de un nodo divergente. Ahora eso
   devuelve `BLOCK`/`FREEZE`, no expulsión.

Además se añadió verificación real **Ed25519 (PyNaCl)**: la firma cubre
`prev_hash || transform_id || timestamp_utc || transformation_hash || seq`, de modo que
una firma válida no puede reutilizarse sobre otro bloque.

## Formato de la petición

```json
{
  "system_id": "sys-001",
  "trajectory": [
    {
      "transform_id": "T1",
      "transformation_hash": "<hex>",
      "actor_signature": "<base64 Ed25519>",
      "actor_id": "actor-A",
      "prev_hash": "0000...0000",
      "timestamp_utc": "2026-10-22T00:00:01Z",
      "seq": 1,
      "events_lost": 0,
      "invariant_check": { "I1": true, "I2": true, "I3": true, "I4": true }
    }
  ],
  "witness_db": {
    "sys-001": [
      { "witness_id": "w0", "seq": 1, "chain_hash": "<hex>" }
    ]
  },
  "actor_keys": { "actor-A": "<hex o base64 de 32 bytes>" },
  "require_signatures": true,
  "f": 2
}
```

- El primer `prev_hash` debe ser el centinela génesis (`"0" * 64`) o el valor declarado
  en `origin_state_S0`.
- Un testigo declara `chain_hash` (recomputó el compromiso completo) **o** `hash`
  (observó el `transformation_hash` crudo). La comparación es homogénea: mezclar ambos
  reportaría una divergencia falsa.
- `f` se deriva de `N` si se omite: `f = (N - 1) // 3`.

## Respuesta

```json
{
  "verdict": "ACCEPT",
  "level": 1,
  "action": "NONE",
  "reason": "chain valid, invariants conserved, witness anchored",
  "trajectory_hash": "<hex>",
  "I5": 1,
  "failing": [],
  "theta_ev": { "nodes": 4, "f": 1, "divergences": 0, "level": 1,
                "recommended_action": "OBSERVE", "consensus_sufficient": true },
  "warnings": []
}
```

## Desarrollo

```bash
pip install -r requirements.txt
pytest                       # 38 tests
python examples/make_trajectory.py > trajectory.json
uvicorn api.validate:app --reload
curl -s -X POST http://127.0.0.1:8000/api/validate \
  -H 'content-type: application/json' -d @trajectory.json
```

## Despliegue

`vercel.json` fija el runtime `python3.12` y reescribe `/` y `/api/validate` a la función.

```bash
vercel --prod
```

## Limitaciones conocidas

- La verificación de firmas está desactivada salvo que se envíe
  `require_signatures: true` con `actor_keys`; en ese caso la respuesta incluye un
  *warning* explícito para que un `ACCEPT` sin firmas no se confunda con un `ACCEPT` completo.
- No hay anclaje externo real (S3 Object Lock, oráculos). `witness_db` es la entrada del
  Lattice, no una fuente de verdad independiente: un atacante que controle el payload
  controla también los anclajes. El anclaje fuera de banda (Cap 8.4) queda pendiente.
- La ventana `xi_t` del Enforcer (Cap 6.3) no se implementa aquí; este servicio emite el
  veredicto, no ejecuta la contención.
