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
            falhas[dados["ip"]].append(para_datetime(dados))
    return falhas

def detectar_forca_bruta(falhas, limite=5, janela=60):
    suspeitos = {}
    for ip, horarios in falhas.items():
        horarios.sort()
        for i in range(len(horarios) - limite + 1):
            if horarios[i + limite - 1] - horarios[i] <= timedelta(seconds=janela):
                suspeitos[ip] = len(horarios)
                break
    return suspeitos

def contar_falhas(caminho):
    contagem = Counter()
    for linha in ler_log(caminho):
        dados = parse_linha(linha)
        if dados:
            contagem[dados["ip"]] += 1
    return contagem

if __name__ == "__main__":
    falhas = coletar_falhas("amostras/auth.log")
    suspeitos = detectar_forca_bruta(falhas, limite=5, janela=60)
    for ip, total in suspeitos.items():
        print(f"SUSPEITO: {ip} ({total} falhas no total)")



