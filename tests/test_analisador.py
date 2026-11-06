from datetime import datetime, timedelta

from analisador import parse_linha, detectar_forca_bruta

LINHA_FALHA = (
    "Nov  4 10:15:01 servidor sshd[1234]: "
    "Failed password for root from 203.0.113.50 port 51234 ssh2"
)
LINHA_USUARIO_INVALIDO = (
    "Nov  4 11:30:05 servidor sshd[1301]: "
    "Failed password for invalid user teste from 198.51.100.7 port 40100 ssh2"
)
LINHA_ACEITA = (
    "Nov  4 08:02:11 servidor sshd[1101]: "
    "Accepted password for maria from 192.0.2.10 port 40011 ssh2"
)


def gerar_falhas(ip, quantidade, intervalo_segundos):
    """Cria falhas fictícias de um IP, uma a cada X segundos."""
    base = datetime(2026, 11, 4, 10, 0, 0)
    return {
        ip: [
            (base + timedelta(seconds=i * intervalo_segundos), "root")
            for i in range(quantidade)
        ]
    }


# --- parse_linha ---

def test_parse_linha_de_falha():
    dados = parse_linha(LINHA_FALHA)
    assert dados["ip"] == "203.0.113.50"
    assert dados["usuario"] == "root"
    assert dados["hora"] == "10:15:01"


def test_parse_usuario_invalido():
    dados = parse_linha(LINHA_USUARIO_INVALIDO)
    assert dados["usuario"] == "teste"
    assert dados["ip"] == "198.51.100.7"


def test_parse_login_aceito_retorna_none():
    assert parse_linha(LINHA_ACEITA) is None


def test_parse_linha_sem_sentido_retorna_none():
    assert parse_linha("isso não é uma linha de log") is None


# --- detectar_forca_bruta ---

def test_detecta_ataque_rapido():
    falhas = gerar_falhas("203.0.113.50", 10, 2)
    resultado = detectar_forca_bruta(falhas, limite=5, janela=120)
    assert len(resultado) == 1
    assert resultado[0]["ip"] == "203.0.113.50"


def test_ignora_falhas_espalhadas():
    falhas = gerar_falhas("192.0.2.33", 3, 3600)
    assert detectar_forca_bruta(falhas, limite=5, janela=120) == []


def test_janela_muda_o_resultado():
    # 6 falhas a cada 25s: 5 falhas seguidas levam 100s
    falhas = gerar_falhas("198.51.100.7", 6, 25)
    assert len(detectar_forca_bruta(falhas, limite=5, janela=120)) == 1
    assert detectar_forca_bruta(falhas, limite=5, janela=60) == []
