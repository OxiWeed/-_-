#!/usr/bin/env python3
# ============================================================
# check_shares_everyone.py
# Verifica se o grupo Everyone ainda tem acesso aos shares
# Domínio: apsen.br | Reteste
# Uso: python3 check_shares_everyone.py -u usuario -p senha -d apsen.br
# ============================================================

import argparse
import csv
import sys
from datetime import datetime

try:
    from impacket.smbconnection import SMBConnection
    from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA
    from impacket.dcerpc.v5 import transport, srvs
    from impacket.dcerpc.v5.dtypes import NULL
except ImportError:
    print("[-] Impacket não encontrado. Instale com: pip install impacket --break-system-packages")
    sys.exit(1)

# ============================================================
# SHARES A VERIFICAR
# ============================================================
SHARES = [
    ("APSAZ042.apsen.br",   "C$"),
    ("APS645.apsen.br",     "EVOLUTIO"),
    ("APS654.apsen.br",     "EVOLUTIO"),
    ("APS471.apsen.br",     "M$"),
    ("APS654.apsen.br",     "F$"),
    ("APSWKVM021.apsen.br", "Users"),
    ("APSAZ042.apsen.br",   "D$"),
    ("APSAZ042.apsen.br",   "M$"),
    ("APS435.apsen.br",     "KLSHARE"),
    ("APS099.apsen.br",     "SCCMApps"),
    ("APS099.apsen.br",     "Forticlient"),
    ("APS099.apsen.br",     "source"),
    ("APS477.apsen.br",     "Tactium_AtuExe"),
    ("APSWKVM011.apsen.br", "Gustavo"),
    ("APSWKVM015.apsen.br", "Users"),
    ("APSWKVM024.apsen.br", "Users"),
    ("APSAZ053.apsen.br",   "SCUA"),
    ("APSAZ053.apsen.br",   "WKLOGS"),
    ("APSSAP011",           "saploc"),
    ("APSAZ048.apsen.br",   "KLSHARE"),
    ("APS025.apsen.br",     "Users"),
    ("APSWKVM005.apsen.br", "TFTP_Bilhetagem"),
]

# Cores ANSI
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def print_banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════╗
║         check_shares_everyone.py — Reteste apsen.br      ║
║         Verifica permissão Everyone nos shares            ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")


def try_connect(host, username, password, domain):
    """Tenta conectar ao host via SMB."""
    try:
        conn = SMBConnection(host, host, timeout=5)
        conn.login(username, password, domain)
        return conn
    except Exception as e:
        return None


def check_share_access(conn, share):
    """
    Tenta acessar o share e verifica nível de acesso.
    Retorna: 'WRITE', 'READ', 'NONE', 'ERROR'
    """
    try:
        # Tentar listar o share (READ)
        conn.listPath(share, "*")
        
        # Tentar criar um arquivo de teste (WRITE)
        test_file = f"__reteste_check_{datetime.now().strftime('%H%M%S')}__.tmp"
        try:
            fid = conn.createFile(share, test_file)
            conn.closeFile(share, fid)
            conn.deleteFiles(share, test_file)
            return "WRITE"
        except Exception:
            return "READ"

    except Exception as e:
        err = str(e).lower()
        if "access_denied" in err or "access denied" in err:
            return "NONE"
        elif "bad_network_name" in err or "bad network" in err:
            return "NOT_FOUND"
        else:
            return f"ERROR: {str(e)[:60]}"


def list_share_permissions(conn, host, share, domain):
    """
    Usa SRVSVC para obter as permissões do share.
    Retorna lista de ACEs com identidade e permissões.
    """
    aces = []
    try:
        rpctransport = transport.SMBTransport(
            host, filename=r'\srvsvc', smb_connection=conn
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)

        resp = srvs.hNetrShareGetInfo(dce, f"\\\\{host}", share, 502)
        
        security_descriptor = resp['InfoStruct']['ShareInfo502']['shi502_security_descriptor']
        if security_descriptor:
            aces.append("ACL disponível via SRVSVC")
        
        dce.disconnect()
    except Exception:
        pass
    
    return aces


def check_null_session(host, share):
    """Verifica se o share é acessível via null session (Everyone sem autenticação)."""
    try:
        conn = SMBConnection(host, host, timeout=5)
        conn.login('', '')
        conn.listPath(share, "*")
        conn.logoff()
        return True
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Verifica permissões Everyone nos shares — Reteste apsen.br'
    )
    parser.add_argument('-u', '--username', required=True, help='Usuário do domínio')
    parser.add_argument('-p', '--password', required=True, help='Senha')
    parser.add_argument('-d', '--domain',   default='apsen.br', help='Domínio (default: apsen.br)')
    parser.add_argument('-o', '--output',   default='reteste_shares.csv', help='Arquivo CSV de saída')
    args = parser.parse_args()

    print_banner()
    print(f"{CYAN}[*] Usuário  : {args.domain}\\{args.username}{RESET}")
    print(f"{CYAN}[*] Total    : {len(SHARES)} shares{RESET}")
    print(f"{CYAN}[*] Saída    : {args.output}{RESET}")
    print("-" * 70)

    results = []
    criticos  = []
    atencao   = []
    corrigidos = []
    inacess   = []

    # Cache de conexões por host
    connections = {}

    for host, share in SHARES:
        share_path = f"\\\\{host}\\{share}"
        print(f"\n[*] Verificando: {share_path}")

        result = {
            "Share":          share_path,
            "Host":           host,
            "ShareName":      share,
            "Acessivel":      False,
            "NullSession":    False,
            "Acesso_Usuario": "",
            "Status":         "",
            "Observacao":     ""
        }

        # 1. Verificar null session (Everyone sem autenticação)
        null = check_null_session(host, share)
        result["NullSession"] = null

        # 2. Conectar com credenciais
        if host not in connections:
            conn = try_connect(host, args.username, args.password, args.domain)
            connections[host] = conn

        conn = connections[host]

        if conn is None:
            result["Acessivel"] = False
            result["Status"]    = "INACESSIVEL"
            result["Observacao"] = "Host não responde ou credenciais inválidas"
            print(f"  {RED}[-] INACESSIVEL — host não responde{RESET}")
            inacess.append(result)
            results.append(result)
            continue

        # 3. Verificar acesso ao share
        access = check_share_access(conn, share)
        result["Acesso_Usuario"] = access

        if access == "WRITE":
            result["Acessivel"] = True
            if null:
                result["Status"]    = "CRITICO"
                result["Observacao"] = "Everyone com WRITE (null session confirmada)"
                print(f"  {RED}[!] CRITICO — Everyone com WRITE (null session ativa){RESET}")
                criticos.append(result)
            else:
                result["Status"]    = "ATENCAO"
                result["Observacao"] = "Usuário autenticado com WRITE — verificar ACL manualmente"
                print(f"  {YELLOW}[!] ATENCAO — WRITE com usuário autenticado{RESET}")
                atencao.append(result)

        elif access == "READ":
            result["Acessivel"] = True
            if null:
                result["Status"]    = "CRITICO"
                result["Observacao"] = "Everyone com READ (null session confirmada)"
                print(f"  {RED}[!] CRITICO — Everyone com READ (null session ativa){RESET}")
                criticos.append(result)
            else:
                result["Status"]    = "ATENCAO"
                result["Observacao"] = "Usuário autenticado com READ — verificar ACL manualmente"
                print(f"  {YELLOW}[!] ATENCAO — READ com usuário autenticado{RESET}")
                atencao.append(result)

        elif access == "NONE":
            result["Acessivel"] = True
            result["Status"]    = "OK"
            result["Observacao"] = "Acesso negado — permissão removida"
            print(f"  {GREEN}[+] OK — acesso negado (corrigido){RESET}")
            corrigidos.append(result)

        elif access == "NOT_FOUND":
            result["Acessivel"] = False
            result["Status"]    = "NOT_FOUND"
            result["Observacao"] = "Share não encontrado no host"
            print(f"  {GRAY}[-] Share não encontrado{RESET}")
            inacess.append(result)

        else:
            result["Acessivel"] = False
            result["Status"]    = "ERRO"
            result["Observacao"] = access
            print(f"  {GRAY}[?] {access}{RESET}")
            inacess.append(result)

        if null:
            print(f"  {RED}    Null Session : ATIVA (Everyone sem autenticação){RESET}")
        else:
            print(f"  {GREEN}    Null Session : Não disponível{RESET}")

        results.append(result)

    # Fechar conexões
    for conn in connections.values():
        if conn:
            try:
                conn.logoff()
            except Exception:
                pass

    # ============================================================
    # RESUMO
    # ============================================================
    print(f"\n{'=' * 70}")
    print(f"{CYAN}{BOLD}RESUMO DO RETESTE{RESET}")
    print(f"{'=' * 70}")
    print(f"  Total verificados  : {len(results)}")
    print(f"  {RED}Críticos           : {len(criticos)}{RESET}")
    print(f"  {YELLOW}Atenção            : {len(atencao)}{RESET}")
    print(f"  {GREEN}Corrigidos (OK)    : {len(corrigidos)}{RESET}")
    print(f"  {GRAY}Inacessíveis/Erro  : {len(inacess)}{RESET}")

    if criticos:
        print(f"\n{RED}[!] Shares CRÍTICOS:{RESET}")
        for r in criticos:
            print(f"  {RED}- {r['Share']} | {r['Observacao']}{RESET}")

    if atencao:
        print(f"\n{YELLOW}[!] Shares com ATENÇÃO:{RESET}")
        for r in atencao:
            print(f"  {YELLOW}- {r['Share']} | {r['Observacao']}{RESET}")

    if corrigidos:
        print(f"\n{GREEN}[+] Shares CORRIGIDOS:{RESET}")
        for r in corrigidos:
            print(f"  {GREEN}- {r['Share']}{RESET}")

    # ============================================================
    # EXPORTAR CSV
    # ============================================================
    with open(args.output, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ["Share", "Host", "ShareName", "Acessivel",
                      "NullSession", "Acesso_Usuario", "Status", "Observacao"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\n{CYAN}[*] Resultado exportado para: {args.output}{RESET}\n")


if __name__ == "__main__":
    main()
