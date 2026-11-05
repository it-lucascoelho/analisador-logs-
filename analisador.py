import re
from collections import Counter

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

def contar_falhas(caminho):
    contagem = Counter()
    for linha in ler_log(caminho):
        dados = parse_linha(linha)
        if dados:
            contagem[dados["ip"]] += 1
    return contagem

if __name__ == "__main__":
    contagem = contar_falhas("amostras/auth.log")
    for ip, total in contagem.most_common(10):
        print(f"{ip}: {total} falhas")