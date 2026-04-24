"""
    Miner de repositorios de tj-actions. Este script se encarga de:
    1. Obtener los 5 repositorios más populares (por estrellas) de tj-actions en GitHub.
    2. Clonar cada repositorio y generar su SBOM utilizando Syft.
    3. Analizar el SBOM con Grype para identificar vulnerabilidades.
    4. Analizar los workflows de GitHub Actions en busca de configuraciones riesgosas.
    5. Guardar los resultados en formato JSON en un directorio específico.
"""
import os
import json
import subprocess
import requests
from datetime import datetime

ORG = "tj-actions"
RESULTS_DIR = "./results"

def obtener_repos():
    print(f"Obteniendo repositorios más populares de {ORG}...")
    
    headers = {}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    todos = []
    page = 1
    while len(todos) < 200:
        url = f"https://api.github.com/orgs/{ORG}/repos?per_page=100&page={page}"
        response = requests.get(url, headers=headers)
        data = response.json()
        if not data:
            break
        todos.extend(data)
        page += 1

    # Filtrar forks y ordenar por estrellas manualmente
    sin_forks = [r for r in todos if not r.get("fork")]
    ordenados = sorted(sin_forks, key=lambda r: r["stargazers_count"], reverse=True)

    repos_validos = []
    for r in ordenados[:5]:
        repos_validos.append({
            "name": r["name"],
            "stars": r["stargazers_count"],
            "language": r.get("language", "N/A"),
            "pushed_at": r.get("pushed_at", ""),
        })

    print(f"Repositorios seleccionados:")
    for r in repos_validos:
        print(f"  - {r['name']} ({r['stars']} estrellas, {r['language']})")

    return repos_validos

def analizar_workflows(destino, repo_name):
    """
    Analiza los workflows de GitHub Actions buscando configuraciones riesgosas.
    Patrones detectados:
      - pull_request_target sin restricciones (HIGH)
      - permissions: write-all (HIGH)
      - acciones referenciadas con @master o @main en vez de SHA/tag (MEDIUM)
      - GITHUB_TOKEN usado sin bloque de permissions explícito (MEDIUM)
      - secrets en variables de entorno (MEDIUM)
      - uso de inputs sin sanitizar en run: (HIGH)
    @param destino: Ruta local del repositorio clonado.
    @param repo_name: Nombre del repositorio.
    @return: Lista de diccionarios con los problemas encontrados.
    """
    workflows_dir = os.path.join(destino, ".github", "workflows")
    problemas = []

    if not os.path.exists(workflows_dir):
        print(f"   No se encontraron workflows en {repo_name}.")
        return problemas

    archivos = [f for f in os.listdir(workflows_dir) if f.endswith((".yml", ".yaml"))]
    print(f"   Analizando {len(archivos)} workflow(s)...")

    for archivo in archivos:
        ruta = os.path.join(workflows_dir, archivo)
        with open(ruta, "r", errors="replace") as f:
            lineas = f.readlines()
        contenido = "".join(lineas)

        def agregar(problema, severidad, linea_num=None):
            entrada = {
                "repo": repo_name,
                "archivo": archivo,
                "problema": problema,
                "severidad": severidad,
                "categoria": "CI/CD workflow",
            }
            if linea_num is not None:
                entrada["linea"] = linea_num
            problemas.append(entrada)

        # Revisar línea por línea
        tiene_permissions = "permissions:" in contenido
        tiene_prt = False

        for i, linea in enumerate(lineas, start=1):
            l = linea.strip()

            # pull_request_target
            if "pull_request_target" in l:
                tiene_prt = True
                agregar("uso de pull_request_target (puede exponer secretos a PRs externos)", "HIGH", i)

            # permisos excesivos
            if "permissions: write-all" in l:
                agregar("permissions: write-all otorga acceso completo de escritura", "HIGH", i)

            if "permissions:" in l and "write-all" not in l:
                # detectar bloques con write en sub-permisos
                pass

            # acciones sin versión fijada a SHA
            if "uses:" in l:
                uses_val = l.split("uses:")[-1].strip()
                if "@master" in uses_val or "@main" in uses_val:
                    agregar(
                        f"acción referenciada con rama flotante ({uses_val}) en vez de SHA fijo",
                        "MEDIUM", i
                    )

            # GITHUB_TOKEN sin bloque de permissions
            if "GITHUB_TOKEN" in l and not tiene_permissions:
                agregar("uso de GITHUB_TOKEN sin bloque de permissions explícito", "MEDIUM", i)

            # secrets expuestos en env
            if "secrets." in l and "env:" in "".join(lineas[max(0, i-3):i+1]):
                agregar("secreto referenciado en bloque env (posible exposición en logs)", "MEDIUM", i)

            # inputs no sanitizados en run
            if "${{" in l and "inputs." in l and "run:" in "".join(lineas[max(0, i-3):i+1]):
                agregar("input de usuario interpolado directamente en run: (riesgo de inyección)", "HIGH", i)

    return problemas


def ejecutar_herramientas(repo_info):
    """
    Clona el repositorio, genera su SBOM con Syft, busca vulnerabilidades
    con Grype y analiza sus workflows de CI/CD.
    @param repo_info: Diccionario con name, stars, language, pushed_at.
    @return: None
    """
    repo_name = repo_info["name"]
    repo_url = f"https://github.com/{ORG}/{repo_name}.git"
    destino = f"./temp_{repo_name}"

    print(f"\nAnalizando: {repo_name}")

    # Clonar
    subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, destino],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Syft — genera SBOM
    sbom_path = f"{RESULTS_DIR}/{repo_name}_sbom.json"
    print("   Generando SBOM...")
    subprocess.run(
        ["syft", destino, "-o", "json", "--file", sbom_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Grype — busca vulnerabilidades
    vulns_path = f"{RESULTS_DIR}/{repo_name}_vulns.json"
    print("   Buscando vulnerabilidades...")
    subprocess.run(
        ["grype", f"sbom:{sbom_path}", "-o", "json", "--file", vulns_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Análisis de workflows
    print("   Analizando workflows CI/CD...")
    problemas_workflows = analizar_workflows(destino, repo_name)
    workflows_path = f"{RESULTS_DIR}/{repo_name}_workflows.json"
    with open(workflows_path, "w") as f:
        json.dump(problemas_workflows, f, indent=2, ensure_ascii=False)
    print(f"   Workflows: {len(problemas_workflows)} problema(s) encontrado(s).")

    # Guardar metadata del repo
    meta_path = f"{RESULTS_DIR}/{repo_name}_meta.json"
    with open(meta_path, "w") as f:
        json.dump({**repo_info, "analizado_en": datetime.utcnow().isoformat() + "Z"}, f, indent=2)

    # Limpiar clon
    subprocess.run(["rm", "-rf", destino])


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    repos = obtener_repos()

    for repo_info in repos:
        ejecutar_herramientas(repo_info)

    print(f"\nAnálisis completo. Resultados guardados en: {RESULTS_DIR}/")
    print("Archivos generados por repositorio:")
    print("  *_sbom.json      — inventario de componentes (SBOM)")
    print("  *_vulns.json     — vulnerabilidades detectadas por Grype")
    print("  *_workflows.json — problemas en workflows de CI/CD")
    print("  *_meta.json      — metadata del repositorio")


if __name__ == "__main__":
    main()
