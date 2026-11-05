def ler_log(caminho):
    with open(caminho, "r", encoding="utf-8") as f:
        for linha in f:
            yield linha.strip()

if __name__ == "__main__":
    for linha in ler_log("amostras/auth.log"):
        print(linha)