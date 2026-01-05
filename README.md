# 👋🏻 Leonardo de Moura Fuseti

Estudante de Defesa Cibernetica no Polo Estacio Piumhi MG . Formação tecnica em Tecnico em Redes de Computadores no IFMG Bambui MG , intusiasta na programação gostando muito de Python e evoluindo dia a dia .

### Conecte-se comigo

[![Perfil DIO](https://img.shields.io/badge/-Meu%20Perfil%20na%20DIO-30A3DC?style=for-the-badge)](https://www.dio.me/users/mourafuseti)
[![E-mail](https://img.shields.io/badge/-Email-000?style=for-the-badge&logo=microsoft-outlook&logoColor=E94D5F)](mailto:mourafuseti@gmail.com)
[![LinkedIn](https://img.shields.io/badge/-LinkedIn-000?style=for-the-badge&logo=linkedin&logoColor=30A3DC)](https://www.linkedin.com/in/leonardo-moura-fuseti-4052b0359/)

### Habilidades

![HTML](https://img.shields.io/badge/HTML-000?style=for-the-badge&logo=html5&logoColor=30A3DC)
![CSS3](https://img.shields.io/badge/CSS3-000?style=for-the-badge&logo=css3&logoColor=E94D5F)
![JavaScript](https://img.shields.io/badge/JavaScript-000?style=for-the-badge&logo=javascript&logoColor=F0DB4F)
![Sass](https://img.shields.io/badge/SASS-000?style=for-the-badge&logo=sass&logoColor=CD6799)
![Bootstrap](https://img.shields.io/badge/bootstrap-000?style=for-the-badge&logo=bootstrap&logoColor=553C7B)
[![Git](https://img.shields.io/badge/Git-000?style=for-the-badge&logo=git&logoColor=E94D5F)](https://git-scm.com/doc)
[![GitHub](https://img.shields.io/badge/GitHub-000?style=for-the-badge&logo=github&logoColor=30A3DC)](https://docs.github.com/)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-black?style=flat&logo=linux)
![Root](https://img.shields.io/badge/Privileges-ROOT%20Required-red)

```markdown
# 👁️ GodEye: Automaton Edition

> **Automated Network Penetration Testing Suite**



O **GodEye Automaton** é uma ferramenta de reconhecimento e análise de vulnerabilidades "One-Click"
desenvolvida em Python.
Ela automatiza todo o ciclo inicial de um Pentest, desde a descoberta da rede até a geração
de relatórios de auditoria,eliminando a necessidade de executar múltiplos comandos manuais do Nmap.

---

## 🚀 Funcionalidades

* **🕵️ Auto-Configuração de Rede:** Deteta automaticamente a interface, Gateway e a sub-rede (CIDR)
sem necessidade de input manual.
* **📡 Host Discovery:** Realiza varredura rápida (Ping Sweep/ARP) para identificar dispositivos vivos.
* **🔍 Deep Scan:** Analisa as **1000 portas** mais comuns, identifica o Sistema Operativo
(OS Fingerprinting) e versões de serviços.
* **💥 Vulnerability Hunter:** Executa scripts NSE (Nmap Scripting Engine) automaticamente para detetar
CVEs conhecidas (Ex: EternalBlue, Heartbleed, FTP Anon).
* **📄 Relatório Automático:** Gera um ficheiro `.txt` organizado com todos os dados coletados ao final
da execução.
* **📊 Feedback Visual:** Barras de progresso em tempo real para acompanhar o ataque.

---

## 🛠️ Pré-requisitos

Esta ferramenta foi desenhada para **Kali Linux** ou **Parrot OS**.

1.  **Nmap:** O binário do Nmap deve estar instalado no sistema.
2.  **Python 3:** A linguagem base do script.
3.  **Privilégios Root:** Necessário para scans SYN (-sS) e deteção de OS (-O).

---

## 📦 Instalação

1.  Clone este repositório:
    ```bash
    git clone [https://github.com/teu-usuario/godeye-automaton.git](https://github.com/teu-usuario/godeye-automaton.git)
    cd godeye-automaton
    ```

2.  Instale as dependências do sistema:
    ```bash
    sudo apt update
    sudo apt install nmap
    ```

3.  Instale as bibliotecas Python necessárias:
    ```bash
    pip install -r requirements.txt
    ```

---

## 💻 Como Usar

Execute sempre com `sudo` (root), caso contrário o script não conseguirá realizar a
deteção de OS nem scans furtivos.

```bash
sudo python3 godeye_automaton.py

```

**O que acontece a seguir?**

1. O script identifica a tua rede (ex: `192.168.1.0/24`).
2. Inicia a descoberta de hosts.
3. Faz a varredura profunda em cada host encontrado.
4. Se encontrar vulnerabilidades, alerta no terminal em **VERMELHO**.
5. Salva o relatório na mesma pasta, exemplo: `GodEye_Report_20241027_1530.txt`.

---

## ⚠️ Aviso Legal (Disclaimer)

**ESTA FERRAMENTA É APENAS PARA FINS EDUCACIONAIS E TESTES AUTORIZADOS.**

O autor não se responsabiliza pelo mau uso ou danos causados por este programa. O uso desta ferramenta 
para atacar alvos sem consentimento mútuo prévio é ilegal. É responsabilidade do usuário final obedecer
a todas as leis locais, estaduais e federais aplicáveis.

---

## 📝 Exemplo de Relatório Gerado

```text
============================================================
RELATÓRIO GODEYE AUTOMATON
Data: 2024-01-05 10:30:00
Rede Auditada: 192.168.0.0/24
============================================================

ALVO: 192.168.0.15
MAC: AA:BB:CC:DD:EE:FF (Dell Inc)
Sistema Operativo: Microsoft Windows 10
--------------------------------------------------
  PORTA    SERVIÇO         VERSÃO
  445      microsoft-ds    Windows 10 Pro 19041

    [!!!] VULNERABILIDADES DETETADAS:
      -> smb-vuln-ms17-010: State: VULNERABLE (EternalBlue)

```

---

**Desenvolvido por Leonardo de Moura Fuseti**





