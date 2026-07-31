# orquestador

Utilidades de línea de comandos para operar sobre publicaciones de MercadoLibre por
fuera del panel web (`server.js`). Sólo usan la biblioteca estándar de Python 3 — no
requieren instalar dependencias.

## `diag_item` — diagnóstico de un cambio de precio

Explica por qué el precio de una publicación podría **no** aplicarse y, opcionalmente,
ejecuta el cambio siguiendo el mismo árbol de decisión que el actualizador masivo del
panel.

```bash
python -m orquestador.diag_item --token <TU_TOKEN> --cuenta EXPRESS \
    --item MLA907803257 --precio 45227
```

Por defecto **no modifica nada**: sólo lee la publicación y reporta.

### Qué detecta

- **Promos activas** (`started/active/…`) que tapan el precio publicado: ML acepta el
  `PUT` pero el precio nuevo no se muestra (falla silenciosa). Es la causa #1.
- **Envío gratis obligatorio**: el precio objetivo cruza el umbral (`--umbral`, default
  `33000`, o env `UMBRAL_ENVIO`) en una publicación Mercado Envío sin envío gratis.
- **Publicación de catálogo / `user_product`**: ML gobierna stock y envío; el precio se
  fija con reintento sólo-precio.
- **Ítems con variaciones**: el precio va dentro de cada variante, no a nivel raíz.
- **Estado** de la publicación y **si ya está en el precio objetivo**.

### Opciones

| Flag | Descripción |
|------|-------------|
| `--token` | Access token de la cuenta ML (requerido). |
| `--item` | ID de la publicación, ej. `MLA907803257` (requerido). |
| `--precio` | Precio objetivo (requerido). |
| `--cuenta` | Etiqueta para el reporte, ej. `EXPRESS`. |
| `--umbral` | Umbral de envío gratis obligatorio (default `33000`). |
| `--aplicar` | Ejecuta el cambio: saca promos aplicadas, manda el precio (con envío gratis / sólo-precio si hace falta) y verifica que haya quedado. |
| `--json` | Salida en JSON, para scripts. |
| `--no-color` | Desactiva colores ANSI. |

### Ejemplos

```bash
# Sólo diagnóstico (no toca nada)
python -m orquestador.diag_item --token $TOK --cuenta EXPRESS --item MLA907803257 --precio 45227

# Diagnóstico + aplicación real del precio
python -m orquestador.diag_item --token $TOK --cuenta EXPRESS --item MLA907803257 --precio 45227 --aplicar

# Salida JSON para integrarlo en otro script
python -m orquestador.diag_item --token $TOK --item MLA907803257 --precio 45227 --json
```

El código de salida es `0` cuando no hay bloqueos (o el `--aplicar` fue exitoso) y `1`
cuando falta una acción, el token es inválido o el cambio no pudo completarse.
