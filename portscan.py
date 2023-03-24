from rich import print as rprint
from rich.console import Console
from rich.prompt import Prompt
from rich.padding import Padding
from rich.prompt import Confirm
import os
import socket
import ipaddress

# Você deverá realizar uma pesquisa dos módulos e bibliotecas que permitem 
# o desenvolvimento de uma ferramenta para o escaneamento de portas TCP 
# de acordo com as premissas a seguir: 

# •	Ser em linguagem Python;
# •	Deverá possuir uma interface amigável e de fácil utilização (user-friendly interface);
# •	Permitir o escaneamento de um host ou uma rede;
# •	Permitir inserir o range (intervalo) de portas a serem escaneadas;
# •	Além da função de escaneamento, espera-se que seu código relacione as portas Well-Known Ports 
#   e seus serviços, e apresente em sua saída (imprimir) o número da porta e o nome do serviço associado.  
# •	Existem diversos projetos e documentações relacionados com esta atividade.
# Aproveite para analisar os códigos já desenvolvidos para teu projeto.

class Scanner:
    def __init__(self):
        self.console = Console()
        # Título do programa
        self.console.print("======================================", style="bold blue", justify="center")
        self.console.print("Port Scanner", style="bold blue", justify="center", highlight=True)
        self.console.print("======================================", style="bold blue", justify="center")
        self.console.print("")

        self.target_host = ""
        self.start_port = 0
        self.end_port = 0

        # Dicionário com as Well-Known Ports
        self.well_known_ports = {
            20: "FTP Data",
            21: "FTP Control",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP Server",
            68: "DHCP Client",
            69: "TFTP",
            80: "HTTP",
            110: "POP3",
            119: "NNTP",
            123: "NTP",
            137: "NetBIOS Name Service",
            138: "NetBIOS Datagram Service",
            139: "NetBIOS Session Service",
            143: "IMAP",
            161: "SNMP",
            162: "SNMP Trap",
            389: "LDAP",
            443: "HTTPS",
            445: "Microsoft-DS",
            465: "SMTPS",
            514: "Syslog",
            515: "Line Printer Daemon",
            587: "SMTP Submission",
            636: "LDAPS",
            993: "IMAPS",
            995: "POP3S",
            1080: "SOCKS Proxy",
            1433: "Microsoft SQL Server",
            1521: "Oracle Database",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP Proxy"
        }

    # Criando IPs
    def create_ips(self, ip, cdir):
        lis_hosts = []
        network = ipaddress.ip_network(ip + "/" + cdir)
        for host in network.hosts():
            lis_hosts.append(str(host))

        return lis_hosts

    def host_scan(self, target_host, start_port, end_port):
        # Armazenando o endereço IP do host alvo e o range de portas a serem escaneadas
        self.target_host = target_host
        self.start_port = int(start_port)
        self.end_port = int(end_port)
        
        if self.start_port > self.end_port:
            self.console.print(f"[bold red]A porta inicial deve ser menor que a final[/bold red]")
            return   

        # Checando se o host é válido
        try:
            socket.gethostbyname(self.target_host)
        except socket.gaierror:
            self.console.print(f"[bold red]O host {self.target_host} não é válido[/bold red]")
            return
     

        # Imprime informações na tela
        print("")
        self.console.print(f"[bold blue]Escaneando o host:[/bold blue] {self.target_host}")
        self.console.print(f"[bold blue]Portas a serem escaneadas:[/bold blue] {self.start_port} - {self.end_port}")
        print("")

        # Realiza o escaneamento
        for port in range(self.start_port, self.end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            print(f"Escaneando a porta {port}...")

            # Verifica se a porta está aberta
            if sock.connect_ex((self.target_host, port)) == 0:
                self.console.print(f"[bold green]Porta {port} aberta[/bold green]")
                # Verifica se a porta está no dicionário
                if port in self.well_known_ports:
                    self.console.print(f"[bold green]Porta {port} aberta - {self.well_known_ports[port]}[/bold green]")
                else:
                    self.console.print(f"[bold green]Porta {port} aberta[/bold green]")

                # Fecha a conexão
                sock.close()

            else:
                # self.console.print(f"[bold red]Porta {port} fechada[/bold red]")

    def network_scan(self, target_host, cidr, start_port, end_port):
        # Armazenando o endereço IP do host alvo e o range de portas a serem escaneadas
        self.target_host = target_host
        self.start_port = int(start_port)
        self.end_port = int(end_port)

        # Imprime informações na tela
        self.console.print(f"[bold blue]Escaneando a rede:[/bold blue] {self.target_host}/{cidr}")
        self.console.print(f"[bold blue]Portas a serem escaneadas:[/bold blue] {self.start_port} - {self.end_port}")
        print("")

        # Lista de hosts
        hosts = self.create_ips(self.target_host, cidr)

        # Realiza o escaneamento
        for host in hosts:
            self.host_scan(host, self.start_port, self.end_port)


        
    def run(self):

        # A qualquer momento, para sair do programa, precione CTRL + C"
        self.console.print("[blue]A qualquer momento, para sair do programa, precione CTRL + C[/blue]", justify="center")
        print("")


        # Opções de escaneamento
        options = ["1 - Escanear um host", "2 - Escanear uma rede", "0 - Sair"]

        # Imprime as opções na tela
        self.console.print("Escolha uma opção digitando o número correspondente", style="bold blue")
        self.console.print(options, style="bold blue")
        print("")

        # Recebe a opção escolhida
        option = Prompt.ask("Digite a opção desejada ")
        print("")
        
        # Verifica a opção escolhida
        if option == "1":
            # Recebe o endereço do host e o range de portas a serem escaneadas
            self.target_host = Prompt.ask("Digite o endereço do host que deseja escanear ")
            print("")

            # Range
            self.start_port = Prompt.ask("Digite a porta inicial do range a ser escaneado ")
            self.end_port = Prompt.ask("Digite a porta final do range a ser escaneado ")

            print("")

            # Realiza o escaneamento
            self.host_scan(self.target_host, self.start_port, self.end_port)

        elif option == "2":
            # Recebe o endereço do host e o range de portas a serem escaneadas
            self.target_host = Prompt.ask("Digite o endereço da rede que deseja escanear ")
            print("")

            # CIDR
            cidr = Prompt.ask("Digite o CIDR da rede a ser escaneada ")
            print("")

            # Range
            self.start_port = Prompt.ask("Digite a porta inicial do range a ser escaneado ")
            self.end_port = Prompt.ask("Digite a porta final do range a ser escaneado ")
            print("")

            # Realiza o escaneamento
            self.network_scan(self.target_host, cidr, self.start_port, self.end_port)

        elif option == "0":
            self.console.print("Saindo...", style="bold blue")
            exit()

        else:
            self.console.print("Opção inválida!", style="bold red")

Scanner().run()