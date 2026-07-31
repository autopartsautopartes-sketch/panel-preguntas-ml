#!/usr/bin/env python3
"""Diagnóstico (y aplicación opcional) de un cambio de precio en una publicación de ML.

Uso:
    python -m orquestador.diag_item --token <TOKEN> --cuenta EXPRESS \
        --item MLA907803257 --precio 45227

Por defecto NO modifica nada: sólo lee la publicación y explica por qué el precio
podría no aplicarse (promo activa que lo tapa, envío gratis obligatorio, publicación
de catálogo, ítem con variaciones, etc.). Con --aplicar ejecuta el mismo árbol de
decisión que el actualizador masivo del panel (server.js): saca las promos aplicadas,
manda el precio (dentro de las variaciones si corresponde), reintenta con envío gratis
o sólo-precio cuando ML lo exige, y verifica que el precio haya quedado realmente.

El diagnóstico replica la lógica de:
  - getActivePromotionsForItemBeforeUpdate / isPromoCurrentlyBlocking
  - removeAppliedPromosProactive (promos "started/active" que tapan el precio)
  - la Fase A de envío gratis por adelantado (UMBRAL_ENVIO_GRATIS, default 33000)
  - tryCatalogPriceOnlyFallback (publicaciones de catálogo)
  - el manejo de ítems con variaciones (el precio va dentro de cada variante)

Sólo usa la biblioteca estándar (urllib) — no requiere dependencias.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.mercadolibre.com"
PROMO_OLD = f"{API}/seller-promotions"
PROMO_MKT = f"{API}/marketplace/seller-promotions"

# Umbral de envío gratis obligatorio (mismo default que server.js: UMBRAL_ENVIO).
UMBRAL_ENVIO_DEFAULT = int(os.environ.get("UMBRAL_ENVIO", "33000") or "33000")

# Estados de promo que se consideran "aplicados" (tapan el precio de la publicación).
PROMO_APLICADA = {"started", "active", "running", "on", "ongoing"}
# Estados claramente terminados/inactivos: no bloquean, no se tocan.
PROMO_TERMINADA = {"finished", "inactive", "deleted", "cancelled", "expired"}


# ---------------------------------------------------------------------------
# Salida por consola
# ---------------------------------------------------------------------------
class C:
    """Códigos ANSI de color. Se desactivan si no hay TTY o con --no-color."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"

    enabled = True

    @classmethod
    def disable(cls):
        cls.enabled = False

    @classmethod
    def paint(cls, txt, *codes):
        if not cls.enabled:
            return txt
        return "".join(codes) + txt + cls.RESET


def _line(char="─", n=64):
    return char * n


# ---------------------------------------------------------------------------
# HTTP contra la API de MercadoLibre
# ---------------------------------------------------------------------------
class MLError(Exception):
    def __init__(self, status, data, url):
        self.status = status
        self.data = data
        self.url = url
        super().__init__(f"HTTP {status} en {url}")


def _request(method, url, token=None, body=None, extra_headers=None):
    """Hace una request y devuelve (status, data_parseada). Lanza MLError en >=400."""
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    data_bytes = None
    if body is not None:
        data_bytes = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", "replace")
            parsed = json.loads(raw) if raw.strip() else {}
            return resp.status, parsed
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        raise MLError(e.code, parsed, url)
    except urllib.error.URLError as e:
        raise MLError(0, {"error": str(e.reason)}, url)


def ml_get(path_or_url, token=None, params=None, extra_headers=None):
    url = path_or_url if path_or_url.startswith("http") else f"{API}{path_or_url}"
    if params:
        sep = "&" if "?" in url else "?"
        url = url + sep + urllib.parse.urlencode(params)
    _, data = _request("GET", url, token=token, extra_headers=extra_headers)
    return data


def ml_put(path_or_url, body, token):
    url = path_or_url if path_or_url.startswith("http") else f"{API}{path_or_url}"
    return _request("PUT", url, token=token, body=body)


# ---------------------------------------------------------------------------
# Helpers de promociones (equivalentes a los de server.js)
# ---------------------------------------------------------------------------
def normalize_promo_list(raw):
    if not raw:
        return []
    if isinstance(raw, list):
        return raw
    for key in ("results", "promotions", "data", "items"):
        if isinstance(raw.get(key), list):
            return raw[key]
    return []


def promo_id(p):
    return str(p.get("id") or p.get("promotion_id") or p.get("offer_id") or p.get("campaign_id") or "")


def promo_type(p):
    return str(p.get("type") or p.get("promotion_type") or p.get("offer_type") or "")


def promo_status(p):
    return str(p.get("status") or p.get("promotion_status") or p.get("state") or "")


def promo_is_blocking(p):
    """Toda promo que no esté claramente terminada se considera potencialmente bloqueante."""
    return promo_status(p).lower() not in PROMO_TERMINADA


def promo_is_applied(p):
    """Promo efectivamente aplicada: la que realmente tapa el precio publicado."""
    return promo_status(p).lower() in PROMO_APLICADA


def obtener_promos(item_id, token, seller_id):
    """Consulta promos de la publicación probando los mismos endpoints que server.js,
    con el token de usuario. Devuelve (promos, fuente, errores)."""
    candidatos = [
        ("old_user_v2", f"{PROMO_OLD}/items/{item_id}?app_version=v2", {}),
        ("old_user_2_0_0", f"{PROMO_OLD}/items/{item_id}?app_version=2.0.0", {}),
    ]
    if seller_id:
        candidatos.append(
            ("marketplace_user_v2", f"{PROMO_MKT}/items/{item_id}?user_id={seller_id}", {"version": "v2"})
        )
    errores = []
    for label, url, headers in candidatos:
        try:
            raw = ml_get(url, token, extra_headers=headers)
            promos = [
                p for p in normalize_promo_list(raw)
                if promo_id(p) and promo_type(p) and promo_is_blocking(p)
            ]
            return promos, label, errores
        except MLError as e:
            errores.append({"tried": label, "status": e.status, "error": _msg_error(e.data)})
    return [], None, errores


def remover_promo(item_id, token, seller_id, promo):
    """DELETE de una promo sobre la publicación (equivalente a
    removePromotionFromItemBeforeUpdate). Sólo se usa en modo --aplicar."""
    pid, ptype = promo_id(promo), promo_type(promo)
    if not pid or not ptype:
        return False, "promoción sin id/type"
    body = {"promotion_id": pid, "promotion_type": ptype}
    candidatos = []
    if seller_id:
        candidatos.append((f"{PROMO_MKT}/items/{item_id}?user_id={seller_id}", {"version": "v2"}))
    candidatos.append((f"{PROMO_OLD}/items/{item_id}?app_version=v2", {}))
    candidatos.append((f"{PROMO_OLD}/items/{item_id}?app_version=2.0.0", {}))
    errores = []
    for url, headers in candidatos:
        for intento in range(4):
            try:
                status, _ = _request("DELETE", url, token=token, body=body, extra_headers=headers)
                return True, None
            except MLError as e:
                if e.status in (204, 404):  # ya no estaba: lo damos por removido
                    return True, None
                errores.append(f"{e.status}: {_msg_error(e.data)}")
                if e.status in (409, 429) or e.status >= 500:
                    time.sleep([1.5, 4, 9, 15][intento])
                    continue
                break
    return False, " | ".join(errores) or "no se pudo remover"


# ---------------------------------------------------------------------------
# Parseo de errores de ML
# ---------------------------------------------------------------------------
def _msg_error(data):
    if not isinstance(data, dict):
        return str(data)
    cause = data.get("cause")
    if isinstance(cause, list) and cause:
        return "; ".join(str(c.get("description") or c.get("code") or c) for c in cause)
    return str(data.get("message") or data.get("error") or data.get("raw") or data)


def es_error_promo(msg):
    s = str(msg).lower()
    señales = ["promotion", "promoción", "promocion", "campaign", "campaña", "offer",
               "deal", "participa", "belongs to", "cannot update price", "price is locked"]
    return any(x in s for x in señales)


# ---------------------------------------------------------------------------
# Diagnóstico
# ---------------------------------------------------------------------------
def resolver_seller_id(token, item):
    """Toma el seller_id del ítem; si no está, lo consulta con /users/me."""
    sid = item.get("seller_id")
    if sid:
        return sid, "item"
    try:
        me = ml_get("/users/me", token)
        return me.get("id"), "users/me"
    except MLError:
        return None, None


def analizar(token, cuenta, item_id, precio_objetivo, umbral):
    """Lee la publicación y arma el diagnóstico. Devuelve un dict estructurado."""
    diag = {
        "cuenta": cuenta,
        "item_id": item_id,
        "precio_objetivo": precio_objetivo,
        "umbral_envio": umbral,
        "problemas": [],   # cosas que impiden/complican el cambio
        "acciones": [],    # qué haría --aplicar
        "notas": [],       # info contextual
    }

    # 1) GET del ítem con todos los atributos relevantes.
    attrs = ("id,title,price,available_quantity,status,seller_id,seller_custom_field,"
             "catalog_product_id,catalog_listing,domain_id,user_product_id,inventory_id,"
             "shipping,variations")
    item = ml_get(f"/items/{item_id}", token, params={"attributes": attrs})
    diag["item"] = item

    seller_id, sid_src = resolver_seller_id(token, item)
    diag["seller_id"] = seller_id
    diag["seller_id_source"] = sid_src

    # 2) Estado actual de precio (raíz y por variación).
    variations = item.get("variations") or []
    tiene_variaciones = len(variations) > 0
    diag["tiene_variaciones"] = tiene_variaciones
    if tiene_variaciones:
        precios_var = [v.get("price") for v in variations if v.get("price") is not None]
        diag["precios_actuales"] = precios_var
        diag["variation_ids"] = [v.get("id") for v in variations if v.get("id")]
        diag["notas"].append(
            f"Ítem con {len(variations)} variación(es): el precio va DENTRO de cada variante, "
            "no a nivel raíz."
        )
    else:
        diag["precios_actuales"] = [item.get("price")]

    # ¿ya está en el objetivo?
    precios = [p for p in diag["precios_actuales"] if p is not None]
    ya_en_objetivo = bool(precios) and all(int(p) == int(precio_objetivo) for p in precios)
    diag["ya_en_objetivo"] = ya_en_objetivo

    # 3) Envío / catálogo.
    shipping = item.get("shipping") or {}
    ship_mode = str(shipping.get("mode") or "").lower()
    logistic_type = str(shipping.get("logistic_type") or "").lower()
    ship_free = shipping.get("free_shipping") is True
    diag["shipping"] = {"mode": ship_mode, "logistic_type": logistic_type, "free_shipping": ship_free}

    es_catalogo = bool(item.get("catalog_listing")) or bool(item.get("user_product_id"))
    diag["es_catalogo"] = es_catalogo
    if es_catalogo:
        diag["notas"].append(
            "Publicación de catálogo / user_product: ML gobierna stock y envío a nivel del "
            "producto de catálogo. El precio SÍ se fija por publicación (reintento sólo-precio)."
        )

    # Cruce del umbral de envío gratis.
    cruza_umbral = (
        precio_objetivo is not None
        and precio_objetivo >= umbral
        and ship_mode == "me2"
        and logistic_type != "self_service"
        and not ship_free
    )
    diag["cruza_umbral_envio"] = cruza_umbral
    if cruza_umbral:
        diag["problemas"].append(
            f"El precio objetivo (${precio_objetivo:,}) supera el umbral de envío gratis "
            f"(${umbral:,}) y la publicación es Mercado Envío sin envío gratis: ML rechazará "
            "el PUT (mandatory_free_shipping) hasta activar envío gratis."
        )
        diag["acciones"].append("Activar envío gratis (mode=me2, free_shipping=true) junto con el precio.")

    # 4) Promociones activas que tapan el precio.
    promos, fuente, errores_promo = obtener_promos(item_id, token, seller_id)
    diag["promos_fuente"] = fuente
    diag["promos_errores"] = errores_promo
    promos_info = [
        {"id": promo_id(p), "type": promo_type(p), "status": promo_status(p),
         "aplicada": promo_is_applied(p)}
        for p in promos
    ]
    diag["promos"] = promos_info
    aplicadas = [p for p in promos if promo_is_applied(p)]
    diag["_promos_aplicadas_raw"] = aplicadas  # para modo --aplicar
    if aplicadas:
        detalle = ", ".join(f"{promo_id(p)}/{promo_type(p)} ({promo_status(p)})" for p in aplicadas)
        diag["problemas"].append(
            f"Hay {len(aplicadas)} promo(s) APLICADA(s) que tapan el precio publicado: {detalle}. "
            "Mientras estén aplicadas, ML acepta el PUT pero el precio nuevo NO se muestra "
            "(falla silenciosa)."
        )
        diag["acciones"].append(
            "Sacar la(s) promo(s) aplicada(s) ANTES de mandar el precio (y volver a cargar tus "
            "promos nuevas después, si querés)."
        )
    elif promos_info:
        diag["notas"].append(
            f"Hay {len(promos_info)} promo(s) OFRECIDA(s) (candidate) pero no aplicadas: no tapan "
            "el precio, no se tocan."
        )

    # 5) Estado de la publicación.
    estado = str(item.get("status") or "")
    diag["estado"] = estado
    if estado not in ("active", "paused"):
        diag["notas"].append(f"Estado de la publicación: '{estado}'.")

    # 6) Veredicto.
    if ya_en_objetivo:
        diag["veredicto"] = "sin_cambios"
    elif diag["problemas"]:
        diag["veredicto"] = "requiere_acciones"
    else:
        diag["veredicto"] = "ok_directo"

    return diag


# ---------------------------------------------------------------------------
# Aplicación (modo --aplicar): replica el árbol de decisión de updateOne()
# ---------------------------------------------------------------------------
def _payload_precio(diag, precio):
    if diag["tiene_variaciones"]:
        return {"variations": [{"id": vid, "price": precio} for vid in diag["variation_ids"]]}
    return {"price": precio}


def verificar_precio(item_id, token, target, es_var):
    """Confirma que ML haya aplicado el precio (fail-closed, como server.js)."""
    tgt = int(target)
    for intento in range(3):
        try:
            it = ml_get(f"/items/{item_id}", token, params={"attributes": "price,variations"})
            variations = it.get("variations") or []
            if es_var and variations:
                precios = [v.get("price") for v in variations if v.get("price") is not None]
                if not precios:
                    p = it.get("price")
                    return p is not None and int(p) == tgt
                return all(int(p) == tgt for p in precios)
            p = it.get("price")
            return p is not None and int(p) == tgt
        except MLError as e:
            if e.status == 429:
                time.sleep([3, 7, 12][intento])
                continue
            return False
    return False


def _put_reintento(item_id, token, payload):
    """PUT con reintentos básicos ante 401/429/409 (versión de un solo ítem)."""
    for intento in range(4):
        try:
            return ml_put(f"/items/{item_id}", payload, token)
        except MLError as e:
            if e.status in (429, 409) or e.status >= 500:
                time.sleep([1.5, 4, 9, 15][intento])
                continue
            raise


def aplicar(diag, token):
    """Ejecuta el cambio de precio siguiendo el mismo orden que el panel."""
    item_id = diag["item_id"]
    seller_id = diag["seller_id"]
    precio = diag["precio_objetivo"]
    es_var = diag["tiene_variaciones"]
    resultado = {"pasos": [], "ok": False}

    if diag["ya_en_objetivo"]:
        resultado["ok"] = True
        resultado["pasos"].append("El precio ya estaba en el objetivo; no se hizo nada.")
        return resultado

    # 0) Sacar promos aplicadas (proactivo).
    for promo in diag["_promos_aplicadas_raw"]:
        ok, err = remover_promo(item_id, token, seller_id, promo)
        if ok:
            resultado["pasos"].append(f"Promo removida: {promo_id(promo)}/{promo_type(promo)}")
        else:
            resultado["pasos"].append(
                f"NO se pudo remover promo {promo_id(promo)}/{promo_type(promo)}: {err}"
            )
    if diag["_promos_aplicadas_raw"]:
        time.sleep(2)  # ML necesita reprocesar antes del PUT de precio

    # 1) PUT del precio (envío gratis por adelantado si cruza el umbral).
    payload = _payload_precio(diag, precio)
    if diag["cruza_umbral_envio"]:
        payload["shipping"] = {"mode": "me2", "free_shipping": True}
    try:
        _put_reintento(item_id, token, payload)
        resultado["pasos"].append(f"PUT precio enviado: {json.dumps(payload, ensure_ascii=False)}")
    except MLError as e:
        msg = _msg_error(e.data)
        resultado["pasos"].append(f"PUT precio falló (HTTP {e.status}): {msg}")
        # Fallback: bloqueo por promo detectado recién ahora → limpiar y reintentar.
        if es_error_promo(msg):
            promos, _, _ = obtener_promos(item_id, token, seller_id)
            for promo in [p for p in promos if promo_is_blocking(p)]:
                remover_promo(item_id, token, seller_id, promo)
            time.sleep(2)
            try:
                _put_reintento(item_id, token, payload)
                resultado["pasos"].append("Reintento tras limpiar promos: OK")
            except MLError as e2:
                resultado["pasos"].append(f"Reintento falló: {_msg_error(e2.data)}")
                return resultado
        elif "shipping" not in payload:
            # Fallback envío gratis obligatorio o catálogo sólo-precio.
            try:
                _put_reintento(item_id, token, {**payload, "shipping": {"mode": "me2", "free_shipping": True}})
                resultado["pasos"].append("Reintento con envío gratis: OK")
            except MLError as e3:
                resultado["pasos"].append(f"Reintento con envío gratis falló: {_msg_error(e3.data)}")
                return resultado
        else:
            return resultado

    # 2) Verificar que el precio haya quedado.
    aplicado = verificar_precio(item_id, token, precio, es_var)
    resultado["ok"] = aplicado
    resultado["pasos"].append(
        "Verificación: precio aplicado ✓" if aplicado
        else "Verificación: el precio NO quedó aplicado (probable promo residual)."
    )
    return resultado


# ---------------------------------------------------------------------------
# Presentación
# ---------------------------------------------------------------------------
def imprimir_diag(diag):
    b = C.paint
    item = diag.get("item", {})
    print()
    print(b(_line("═"), C.CYAN))
    print(b(f" DIAGNÓSTICO · {diag['item_id']}  ({diag['cuenta']})", C.BOLD, C.CYAN))
    print(b(_line("═"), C.CYAN))
    print(f"  Título        : {item.get('title', '?')}")
    print(f"  Estado        : {diag.get('estado', '?')}")
    print(f"  Seller ID     : {diag.get('seller_id', '?')} ({diag.get('seller_id_source') or 's/d'})")
    precios = ", ".join(str(p) for p in diag.get("precios_actuales", []) if p is not None)
    print(f"  Precio actual : {precios or 's/d'}")
    print(f"  Precio nuevo  : {b(str(diag['precio_objetivo']), C.BOLD)}")
    print(f"  Variaciones   : {'sí (' + str(len(diag.get('variation_ids', []))) + ')' if diag['tiene_variaciones'] else 'no'}")
    print(f"  Catálogo      : {'sí' if diag['es_catalogo'] else 'no'}")
    sh = diag.get("shipping", {})
    print(f"  Envío         : mode={sh.get('mode') or 's/d'} logistic={sh.get('logistic_type') or 's/d'} gratis={sh.get('free_shipping')}")
    promos = diag.get("promos", [])
    if promos:
        print(f"  Promos        : {len(promos)} (fuente: {diag.get('promos_fuente')})")
        for p in promos:
            tag = b("APLICADA", C.RED, C.BOLD) if p["aplicada"] else b("ofrecida", C.DIM)
            print(f"                  - {p['id']}/{p['type']} [{p['status']}] {tag}")
    else:
        print(f"  Promos        : ninguna bloqueante")

    if diag.get("problemas"):
        print()
        print(b("  ⚠ PROBLEMAS DETECTADOS", C.YELLOW, C.BOLD))
        for x in diag["problemas"]:
            print(b("   • ", C.YELLOW) + x)
    if diag.get("acciones"):
        print()
        print(b("  → ACCIONES QUE HARÍA --aplicar", C.BLUE, C.BOLD))
        for x in diag["acciones"]:
            print(b("   • ", C.BLUE) + x)
    if diag.get("notas"):
        print()
        print(b("  ℹ NOTAS", C.DIM, C.BOLD))
        for x in diag["notas"]:
            print(b("   • " + x, C.DIM))
    if diag.get("promos_errores"):
        print()
        print(b("  (endpoints de promo que fallaron):", C.DIM))
        for e in diag["promos_errores"]:
            print(b(f"    - {e['tried']}: HTTP {e['status']} {e['error']}", C.DIM))

    print()
    ver = diag["veredicto"]
    if ver == "sin_cambios":
        print(b("  VEREDICTO: el precio ya está en el objetivo. Nada que hacer.", C.GREEN, C.BOLD))
    elif ver == "ok_directo":
        print(b("  VEREDICTO: sin bloqueos. El precio debería aplicarse con un PUT directo.", C.GREEN, C.BOLD))
    else:
        print(b("  VEREDICTO: requiere acciones (ver arriba) para que el precio se aplique.", C.YELLOW, C.BOLD))
    print(b(_line("═"), C.CYAN))
    print()


def imprimir_aplicacion(res):
    b = C.paint
    print(b("  APLICANDO CAMBIO…", C.BOLD))
    for paso in res["pasos"]:
        print("   • " + paso)
    print()
    if res["ok"]:
        print(b("  ✓ Precio aplicado correctamente.", C.GREEN, C.BOLD))
    else:
        print(b("  ✗ El cambio no se completó. Revisá los pasos de arriba.", C.RED, C.BOLD))
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="python -m orquestador.diag_item",
        description="Diagnostica (y opcionalmente aplica) un cambio de precio en una "
                    "publicación de MercadoLibre.",
    )
    p.add_argument("--token", required=True, help="Access token de la cuenta ML.")
    p.add_argument("--cuenta", default="", help="Etiqueta de la cuenta (solo para el reporte, ej. EXPRESS).")
    p.add_argument("--item", required=True, help="ID de la publicación (ej. MLA907803257).")
    p.add_argument("--precio", required=True, type=float, help="Precio objetivo.")
    p.add_argument("--umbral", type=int, default=UMBRAL_ENVIO_DEFAULT,
                   help=f"Umbral de envío gratis obligatorio (default {UMBRAL_ENVIO_DEFAULT}).")
    p.add_argument("--aplicar", action="store_true",
                   help="Ejecuta el cambio (por defecto sólo diagnostica, sin modificar nada).")
    p.add_argument("--json", action="store_true", help="Salida en JSON (para scripts).")
    p.add_argument("--no-color", action="store_true", help="Desactiva colores ANSI.")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_color or args.json or not sys.stdout.isatty():
        C.disable()

    precio = int(args.precio) if float(args.precio).is_integer() else args.precio

    try:
        diag = analizar(args.token, args.cuenta or "s/d", args.item, precio, args.umbral)
    except MLError as e:
        msg = _msg_error(e.data)
        if e.status == 401:
            hint = "Token inválido o expirado: reconectá la cuenta / pedí un token nuevo."
        elif e.status == 404:
            hint = "La publicación no existe o no pertenece a esta cuenta/token."
        else:
            hint = msg
        if args.json:
            print(json.dumps({"error": hint, "status": e.status, "detalle": msg}, ensure_ascii=False, indent=2))
        else:
            print(C.paint(f"\n  ✗ No se pudo leer la publicación (HTTP {e.status}): {hint}\n", C.RED, C.BOLD))
        return 1

    res_aplicar = None
    if args.aplicar:
        res_aplicar = aplicar(diag, args.token)

    if args.json:
        out = {k: v for k, v in diag.items() if not k.startswith("_")}
        if res_aplicar is not None:
            out["aplicacion"] = res_aplicar
        print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
    else:
        imprimir_diag(diag)
        if res_aplicar is not None:
            imprimir_aplicacion(res_aplicar)

    if res_aplicar is not None:
        return 0 if res_aplicar["ok"] else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
