"""orquestador — utilidades de línea de comandos para operar sobre publicaciones
de MercadoLibre por fuera del panel web (server.js).

Módulos:
  - diag_item: diagnostica (y opcionalmente aplica) un cambio de precio sobre una
    publicación, replicando el árbol de decisión del actualizador masivo del panel
    (promos activas que tapan el precio, envío gratis obligatorio, publicaciones de
    catálogo, ítems con variaciones, etc.).
"""

__all__ = ["diag_item"]
__version__ = "1.0.0"
