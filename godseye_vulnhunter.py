import nmap
import netifaces
from colorama import Fore, Style, init
from prettytable import PrettyTable
import sys
import os
import time

# Inicialização
init(autoreset=True)

class GodEyeVulnHunter:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.target = ""

    def clear_screen(self):
        os.system('clear')

    def print_banner(self):
        print(Fore.RED + Style.BRIGHT + """
        =========================================================
          G O D   E Y E   -   V U L N   H U N T E R
          (Scanner de Vulnerabilidades Tático)
        =========================================================
        """)

    def set_target(self):
        print(Fore.CYAN + "[CONFIGURAÇÃO DO ALVO]")
        # Opção para escanear a rede toda ou um IP só
        choice = input("Deseja escanear a rede inteira (1) ou um IP único (2)? ")
        
        if choice == '1':
            try:
                gws = netifaces.gateways()
                gateway = gws['default'][netifaces.AF_INET][0]
                ip_parts = gateway.split('.')
                self.target = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                print(Fore.GREEN + f"[*] Alvo Rede: {self.target}")
            except:
                self.target = input("Digite o range (ex: 192.168.1.0/24): ")
        else:
            self.target = input("Digite o IP do Alvo (ex: 192.168.1.15): ")

    def run_scan(self, category, description):
        self.clear_screen()
        self.print_banner()
        print(Fore.YELLOW + f"[!] INICIANDO CAÇADA: {description}")
        print(Fore.WHITE + f"[*] Alvo: {self.target}")
        print(Fore.WHITE + "[*] Isso pode demorar... Aguarde.")

        # Executa o scan com scripts específicos
        # --script: Define a categoria ou scripts específicos
        try:
            # -Pn: Não pingar (assume online)
            # --script-args=unsafe=1: Alguns scripts precisam disso para serem eficazes (CUIDADO EM PRODUÇÃO)
            self.nm.scan(self.target, arguments=f'-sV -Pn --script {category}')
            
            self.show_results()
        except Exception as e:
            print(Fore.RED + f"Erro crítico: {e}")

    def show_results(self):
        print(Fore.YELLOW + "\n[RESULTADOS ENCONTRADOS]")
        found_vulns = False

        for host in self.nm.all_hosts():
            print(Fore.BLUE + "-" * 50)
            print(Fore.BLUE + f"HOST: {host} ({self.nm[host].hostname()})")
            
            if 'tcp' in self.nm[host]:
                for port, data in self.nm[host]['tcp'].items():
                    if 'script' in data:
                        found_vulns = True
                        print(Fore.RED + f"\n  [PORTA {port}] - {data['name']}")
                        for script_id, output in data['script'].items():
                            print(Fore.LIGHTRED_EX + f"    > {script_id}")
                            # Formata o output para ficar legível
                            clean_output = output.replace("\n", "\n      ")
                            print(Fore.WHITE + f"      {clean_output}")
        
        if not found_vulns:
            print(Fore.GREEN + "Nenhuma vulnerabilidade óbvia encontrada nesta categoria.")
        
        input(Fore.CYAN + "\n[Pressione ENTER para voltar ao menu]")

    def menu(self):
        while True:
            self.clear_screen()
            self.print_banner()
            if not self.target:
                self.set_target()
            
            print(Fore.CYAN + f"\n[ALVO ATUAL: {self.target}]")
            print(Fore.WHITE + "Escolha o vetor de ataque:")
            print("1. Vulnerabilidades Windows (SMB, RDP, EternalBlue)")
            print("2. Vulnerabilidades Web (SQLi, XSS, Wordpress, PHP)")
            print("3. Vulnerabilidades de Autenticação (Default Creds, FTP Anon)")
            print("4. Vulnerabilidades SSL/TLS (Heartbleed, Poodle)")
            print("5. Malware Discovery (Backdoors, Botnets conhecidas)")
            print("6. Scan 'Exploit' (Tenta achar falhas com exploits públicos)")
            print("9. Mudar Alvo")
            print("0. Sair")

            opt = input(Fore.YELLOW + "\nGodEye > ")

            if opt == '1':
                # Foca em SMB e vulnerabilidades conhecidas de infra Windows
                self.run_scan("smb-vuln*,rdp-vuln*", "Windows Infrastructure")
            elif opt == '2':
                # Foca em serviços HTTP e scripts de vulnerabilidade web
                self.run_scan("http-vuln*,http-sql-injection,http-xss*", "Web Applications")
            elif opt == '3':
                # Procura por credenciais padrão (FTP, Telnet, HTTP) e acesso anônimo
                self.run_scan("ftp-anon,http-default-accounts,telnet-brute", "Authentication & Defaults")
            elif opt == '4':
                # Checa a segurança da criptografia
                self.run_scan("ssl-heartbleed,ssl-poodle,ssl-enum-ciphers", "SSL/TLS Security")
            elif opt == '5':
                # Verifica se o host está infectado ou agindo estranho
                self.run_scan("malware,auth-spoof", "Malware & Backdoors")
            elif opt == '6':
                # Categoria 'exploit' do Nmap: Procura falhas que têm exploit conhecido
                self.run_scan("exploit", "Known Exploits (High Risk)")
            elif opt == '9':
                self.target = ""
            elif opt == '0':
                sys.exit()

if __name__ == "__main__":
    # Verifica se é root para ter permissão de scans RAW
    if os.geteuid() != 0:
        print(Fore.RED + "Execute como ROOT (sudo) para scans de vulnerabilidade.")
    else:
        app = GodEyeVulnHunter()
        app.menu()