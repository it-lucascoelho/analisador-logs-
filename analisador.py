import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

PADRAO_FALHA = re.compile(
    r"^(?P<mes>\w{3})\s+(?P<dia>\d+)\s+(?P<hora>[\d:]+).*"
    r"Failed password for (?:invalid user )?(?P<usuario>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def ler_log(caminho):
    with open(caminho, "r", encoding="utf-8") as f:
        for linha in f:
            yield linha.strip()

def parse_linha(linha):
    m = PADRAO_FALHA.search(linha)
    return m.groupdict() if m else None

MESES = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
         "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

def para_datetime(dados):
    hora, minuto, segundo = map(int, dados["hora"].split(":"))
    return datetime(
        datetime.now().year,
        MESES[dados["mes"]],
        int(dados["dia"]),
        hora, minuto, segundo,
    )

def coletar_falhas(caminho):
    falhas = defaultdict(list)
    for linha in ler_log(caminho):
        dados = parse_linha(linha)
        if dados:
            falhas[dados["ip"]].append((para_datetime(dados), dados["usuario"]))
    return falhas

def detectar_forca_bruta(falhas, limite=5, janela=120):
    suspeitos = []
    for ip, registros in falhas.items():
        registros.sort()
        horarios = [h for h, _ in registros]
        for i in range(len(horarios) - limite + 1):
            if horarios[i + limite - 1] - horarios[i] <= timedelta(seconds=janela):
                suspeitos.append({
                    "ip": ip,
                    "total_falhas": len(registros),
                    "primeiro_horario": horarios[0].strftime("%d/%m %H:%M:%S"),
                    "ultimo_horario": horarios[-1].strftime("%d/%m %H:%M:%S"),
                    "usuarios_tentados": sorted({u for _, u in registros}),
                })
                break
    return suspeitos

def salvar_json(suspeitos, caminho):
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(suspeitos, f, indent=2, ensure_ascii=False)

def salvar_csv(suspeitos, caminho):
    campos = ["ip", "total_falhas", "primeiro_horario",
              "ultimo_horario", "usuarios_tentados"]
    with open(caminho, "w", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=campos)
        escritor.writeheader()
        for s in suspeitos:
            linha = dict(s)
            linha["usuarios_tentados"] = ";".join(s["usuarios_tentados"])
            escritor.writerow(linha)

def contar_falhas(caminho):
    contagem = Counter()
    for linha in ler_log(caminho):
        dados = parse_linha(linha)
        if dados:
            contagem[dados["ip"]] += 1
    return contagem

def main():
    parser = argparse.ArgumentParser(
        description="Detecta ataques de força bruta em logs SSH (MITRE ATT&CK T1110)."
    )
    parser.add_argument("log", help="caminho do arquivo de log")
    parser.add_argument("--limite", type=int, default=5,
                        help="número de falhas para considerar ataque (padrão: 5)")
    parser.add_argument("--janela", type=int, default=120,
                        help="janela de tempo em segundos (padrão: 120)")
    parser.add_argument("--saida",
                        help="arquivo de saída (.csv ou .json)")
    args = parser.parse_args()

    falhas = coletar_falhas(args.log)
    suspeitos = detectar_forca_bruta(falhas, args.limite, args.janela)

    if not suspeitos:
        print("Nenhum IP suspeito encontrado.")
        return

    for s in suspeitos:
        print(f"SUSPEITO: {s['ip']} | {s['total_falhas']} falhas | "
              f"{s['primeiro_horario']} a {s['ultimo_horario']} | "
              f"usuários: {', '.join(s['usuarios_tentados'])}")

    if args.saida:
        if args.saida.endswith(".json"):
            salvar_json(suspeitos, args.saida)
        else:
            salvar_csv(suspeitos, args.saida)
        print(f"Relatório salvo em {args.saida}")

if __name__ == "__main__":
    main()



