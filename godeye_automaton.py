import nmap
import netifaces
import socket
import sys
import os
import datetime
from colorama import Fore, Style, init
from prettytable import PrettyTable
from tqdm import tqdm

# Inicialização de cores
init(autoreset=True)

class GodEyeAutomaton:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_data = {}
        self.network = ""
        self.gateway = ""
        self.interface = ""
        self.start_time = datetime.datetime.now()
        self.filename = f"GodEye_Report_{self.start_time.strftime('%Y%m%d_%H%M')}.txt"

    def clear_screen(self):
        os.system('clear')

    def print_banner(self):
        print(Fore.RED + Style.BRIGHT + """
        ██████╗  ██████╗  ██████╗     ██████╗  ██╗   ██╗███████╗
        ██╔════╝ ██╔═══██╗██╔══██╗    ██╔═══██╗╚██╗ ██╔╝██╔════╝
        ██║  ███╗██║   ██║██║  ██║    ███████╔╝ ╚████╔╝ █████╗  
        ██║   ██║██║   ██║██║  ██║    ██╔══██╗   ╚██╔╝  ██╔══╝  
        ╚██████╔╝╚██████╔╝██████╔╝    ██║  ██║    ██║   ███████╗
         ╚═════╝  ╚═════╝ ╚═════╝     ╚═╝  ╚═╝    ╚═╝   ╚══════╝
        [ A U T O M A T O N   E D I T I O N ]
        """)

    def auto_config(self):
        print(Fore.CYAN + "[*] A iniciar auto-configuração de rede...")
        try:
            # Deteta o gateway padrão e a interface
            gws = netifaces.gateways()
            self.gateway = gws['default'][netifaces.AF_INET][0]
            self.interface = gws['default'][netifaces.AF_INET][1]
            
            # Reconstrói a sub-rede (Assume /24 para redes locais domésticas/pequenas empresas)
            ip_parts = self.gateway.split('.')
            self.network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            print(Fore.GREEN + f"    [+] Interface: {self.interface}")
            print(Fore.GREEN + f"    [+] Gateway: {self.gateway}")
            print(Fore.GREEN + f"    [+] Alvo Definido: {self.network}")
            
        except Exception as e:
            print(Fore.RED + f"    [!] Erro na deteção automática: {e}")
            sys.exit()

    def phase_1_discovery(self):
        print(Fore.YELLOW + "\n[FASE 1] A descobrir anfitriões (Host Discovery)...")
        
        # Ping scan rápido
        with tqdm(total=100, desc="Ping Sweep", bar_format="{l_bar}{bar}|", colour='green') as pbar:
            self.nm.scan(hosts=self.network, arguments='-sn -PE -T4')
            pbar.update(100)
            
        hosts = self.nm.all_hosts()
        print(Fore.GREEN + f"    [+] {len(hosts)} dispositivos encontrados.")
        
        # Inicializa a estrutura de dados
        for host in hosts:
            self.scan_data[host] = {
                'mac': 'Desconhecido',
                'vendor': 'Desconhecido',
                'os': 'Desconhecido',
                'tcp': []
            }

    def phase_2_full_audit(self):
        print(Fore.YELLOW + "\n[FASE 2] Auditoria Completa (Portas, SO e Vulnerabilidades)...")
        print(Fore.WHITE + "    [*] A executar: Deteção de Versão (-sV), SO (-O) e Scripts de Vuln (--script vuln)")
        
        hosts_list = list(self.scan_data.keys())
        
        # Barra de progresso para cada IP
        with tqdm(total=len(hosts_list), desc="Scanning", unit="alvo", colour='red') as pbar:
            for ip in hosts_list:
                pbar.set_description(f"A analisar {ip}")
                
                try:
                    # O COMANDO PESADO:
                    # -sS: SYN Scan (Stealth)
                    # -sV: Versão
                    # -O: SO
                    # --top-ports 1000: As 1000 portas mais usadas
                    # --script vuln: Roda todos os scripts da categoria 'vuln'
                    # -T4: Timing agressivo
                    self.nm.scan(ip, arguments='-sS -sV -O --top-ports 1000 --script vuln -T4')
                    
                    # 1. Captura MAC e Fabricante
                    if 'addresses' in self.nm[ip] and 'mac' in self.nm[ip]['addresses']:
                        self.scan_data[ip]['mac'] = self.nm[ip]['addresses']['mac']
                        if 'vendor' in self.nm[ip]:
                             vendors = self.nm[ip]['vendor']
                             if vendors:
                                 self.scan_data[ip]['vendor'] = list(vendors.values())[0]

                    # 2. Captura SO
                    if 'osmatch' in self.nm[ip] and self.nm[ip]['osmatch']:
                        self.scan_data[ip]['os'] = self.nm[ip]['osmatch'][0]['name']

                    # 3. Captura Portas e Vulns
                    if 'tcp' in self.nm[ip]:
                        for port, data in self.nm[ip]['tcp'].items():
                            if data['state'] == 'open':
                                vulns = []
                                # Verifica saída de scripts
                                if 'script' in data:
                                    for script_id, output in data['script'].items():
                                        # Formata para ficar limpo no relatório
                                        clean_out = output.replace('\n', ' ').strip()
                                        vulns.append(f"{script_id}: {clean_out[:100]}...") # Corta se for mt longo
                                
                                port_info = {
                                    'id': port,
                                    'service': data['name'],
                                    'version': f"{data['product']} {data['version']}",
                                    'vulns': vulns
                                }
                                self.scan_data[ip]['tcp'].append(port_info)
                                
                                if vulns:
                                    tqdm.write(Fore.RED + f"    [!] VULN ENCONTRADA EM {ip}:{port}")

                except Exception as e:
                    tqdm.write(Fore.RED + f"Erro ao analisar {ip}: {e}")
                
                pbar.update(1)

    def generate_report(self):
        print(Fore.CYAN + f"\n[*] A gerar relatório automático: {self.filename}...")
        
        with open(self.filename, 'w') as f:
            f.write("="*60 + "\n")
            f.write(f"RELATÓRIO GODEYE AUTOMATON\n")
            f.write(f"Data: {self.start_time}\n")
            f.write(f"Rede Auditada: {self.network}\n")
            f.write("="*60 + "\n\n")
            
            for ip, data in self.scan_data.items():
                f.write(f"ALVO: {ip}\n")
                f.write(f"MAC: {data['mac']} ({data['vendor']})\n")
                f.write(f"Sistema Operativo: {data['os']}\n")
                f.write("-" * 50 + "\n")
                
                if not data['tcp']:
                    f.write("  Nenhuma porta aberta detetada (Top 1000).\n")
                else:
                    f.write(f"  {'PORTA':<8} {'SERVIÇO':<15} {'VERSÃO'}\n")
                    for p in data['tcp']:
                        f.write(f"  {p['id']:<8} {p['service']:<15} {p['version']}\n")
                        
                        if p['vulns']:
                            f.write("\n    [!!!] VULNERABILIDADES DETETADAS:\n")
                            for v in p['vulns']:
                                f.write(f"      -> {v}\n")
                            f.write("\n")
                f.write("\n" + "="*60 + "\n\n")
        
        print(Fore.GREEN + "[SUCESSO] Relatório guardado com sucesso.")

    def run(self):
        self.clear_screen()
        self.print_banner()
        
        # O fluxo automatizado
        self.auto_config()
        self.phase_1_discovery()
        self.phase_2_full_audit()
        self.generate_report()
        
        print(Fore.WHITE + "\n[FIM] Processo concluído. Verifica o ficheiro .txt gerado.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(Fore.RED + "ERRO DE PERMISSÃO: Execute como ROOT (sudo python3 godeye_automaton.py)")
        sys.exit()
        
    bot = GodEyeAutomaton()
    bot.run()