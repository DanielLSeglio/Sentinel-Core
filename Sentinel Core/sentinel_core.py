import re
import io
import socket
import struct
import ipaddress
from datetime import datetime, timedelta
import ast
import json
import subprocess
import time

import pandas as pd
import requests
import streamlit as st
import matplotlib.pyplot as plt

# Folium é opcional
try:
    import folium
    from streamlit_folium import st_folium
    FOLIUM_AVAILABLE = True
except Exception:
    FOLIUM_AVAILABLE = False





# ===============================
# Streamlit UI
# ===============================
st.set_page_config(page_title="🛡️ SENTINEL-CORE Dashboard", layout="wide")
st.title("🛡️ SENTINEL-CORE Dashboard")
st.write("Análise de logs, correlação temporal e enriquecimento com Threat Intelligence.")

# Sidebar: opção de limite de IPs para consulta (0 = sem consultas)
with st.sidebar:
    st.header("Configurações")
    MAX_IPS_TO_QUERY = st.number_input("Máx. de IPs a consultar (0 = desativado)", min_value=0, max_value=10000, value=100, step=10)
    BATCH_SIZE = st.number_input("Batch size para pausas (requests por batch)", min_value=1, max_value=100, value=10)
    BATCH_SLEEP = st.number_input("Sleep (seg) entre batches", min_value=0.0, max_value=10.0, value=1.0, step=0.1)





# ===============================
# Configurações (substitua por suas chaves)
# ===============================
ABUSEIPDB_API_KEY = ""
VIRUSTOTAL_API_KEY = ""





# ===============================
# Funções utilitárias (hex -> ipv4)
# ===============================
def clean_hex(s):
    if s is None:
        return ""
    return re.sub(r'[^0-9a-fA-F]', '', str(s)).lower()

def rev_bytes(hex8):
    return "".join([hex8[i:i+2] for i in range(6, -1, -2)])

def ipv4_from_hex8(hex8):
    try:
        return socket.inet_ntoa(struct.pack("!L", int(hex8, 16)))
    except Exception:
        return None

def hexstr_to_ipv4_candidates(hex_str):
    """Gera candidatos a partir de um token hex — mais conservador (tamanho controlado)."""
    h = clean_hex(hex_str)
    if len(h) < 8:
        return []
    # limitar tokens muito longos para evitar interpretações errôneas
    if len(h) > 32:
        return []
    candidates_hex = []
    first8, last8 = h[:8], h[-8:]
    candidates_hex.extend([last8, first8, rev_bytes(last8), rev_bytes(first8)])
    if len(h) >= 10:
        mid8 = h[2:10]
        candidates_hex.extend([mid8, rev_bytes(mid8)])
    unique_hex = list(dict.fromkeys(filter(None, candidates_hex)))
    candidates = []
    for hx in unique_hex:
        ip = ipv4_from_hex8(hx)
        if ip:
            candidates.append(ip)
    return candidates

def is_public_ipv4(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_multicast or a.is_reserved or a.is_unspecified or a.is_link_local)
    except Exception:
        return False

def convert_hex_like_to_ipv4(hex_like):
    """Tenta decodificar uma token hex -> IPv4 de forma conservadora."""
    if not hex_like:
        return None
    # se for lista textual (ex: "['0x7f000001', ...]") tentar parse
    if isinstance(hex_like, str) and (hex_like.strip().startswith('[') or hex_like.strip().startswith('{')):
        try:
            parsed = ast.literal_eval(hex_like)
            if isinstance(parsed, (list, tuple)):
                # preferir primeiro valor decodificável e público
                for token in parsed:
                    for ip in hexstr_to_ipv4_candidates(str(token)):
                        if is_public_ipv4(ip):
                            return ip
                # fallback: primeiro candidato
                for token in parsed:
                    cands = hexstr_to_ipv4_candidates(str(token))
                    if cands:
                        return cands[0]
        except Exception:
            # se falhar, continuar com heurística normal
            pass

    # se vier como csv/strings separadas por vírgula, tentar separar
    if isinstance(hex_like, str) and (',' in hex_like or ' ' in hex_like):
        tokens = re.split(r'[,\s]+', hex_like.strip())
    else:
        tokens = [hex_like]

    for token in tokens:
        token = token.strip()
        if not token:
            continue
        # se já for um IPv4 textual, retorna diretamente
        if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', token):
            try:
                if all(0 <= int(p) <= 255 for p in token.split('.')):
                    return token
            except Exception:
                pass
        # apenas tente converter tokens com tamanho razoável
        if 8 <= len(clean_hex(token)) <= 32:
            cands = hexstr_to_ipv4_candidates(token)
            for ip in cands:
                if is_public_ipv4(ip):
                    return ip
            if cands:
                return cands[0]
    return None





# ===============================
# Extração de IPs
# ===============================
def extract_and_decode_ips(text_data):
    """
    Extração conservadora:
    - Se text_data é uma string que representa dict/list, parseamos e extraímos apenas de campos conhecidos.
    - Se não é dict/list, só extraímos IPs se o texto contem keywords que indicam presença de IPs.
    - Não varrermos todo o 'raw' por tokens hex indiscriminadamente.
    """
    found = set()
    s = str(text_data)
    s_lower = s.lower()

    # tenta detectar estruturas JSON/python dict e extrair valores apenas dos campos de interesse
    parsed = None
    try:
        if (s.strip().startswith('{') and s.strip().endswith('}')) or (s.strip().startswith('[') and s.strip().endswith(']')):
            try:
                parsed = ast.literal_eval(s)
            except Exception:
                try:
                    parsed = json.loads(s)
                except Exception:
                    parsed = None
    except Exception:
        parsed = None

    candidate_fields = ['sample source ip', 'sample source ip (ipv4)', 'sample_source_ip', 'sample_from', 'sample to', 'sample from', 'sample from', 'sample title', 'from', 'to', 'source', 'ip', 'sample sha256']

    if isinstance(parsed, dict):
        for k, v in parsed.items():
            key = str(k).lower()
            # só processa campos que possuam nomes relevantes
            if any(cf in key for cf in candidate_fields):
                # tratar listas/tuplas
                if isinstance(v, (list, tuple)):
                    for token in v:
                        if token is None:
                            continue
                        token_str = str(token)
                        # tenta decode hex primero
                        if ip := convert_hex_like_to_ipv4(token_str):
                            found.add(ip)
                        # se já for um ipv4 textual
                        for ip_match in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', token_str):
                            try:
                                if all(0 <= int(p) <= 255 for p in ip_match.split('.')):
                                    found.add(ip_match)
                            except Exception:
                                continue
                else:
                    token_str = str(v)
                    if ip := convert_hex_like_to_ipv4(token_str):
                        found.add(ip)
                    for ip_match in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', token_str):
                        try:
                            if all(0 <= int(p) <= 255 for p in ip_match.split('.')):
                                found.add(ip_match)
                        except Exception:
                            continue

    elif isinstance(parsed, list):
        # lista de tokens --> tentar decodificar cada token, mas com limite conservador
        for token in parsed:
            if token is None:
                continue
            token_str = str(token)
            if ip := convert_hex_like_to_ipv4(token_str):
                found.add(ip)
            for ip_match in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', token_str):
                try:
                    if all(0 <= int(p) <= 255 for p in ip_match.split('.')):
                        found.add(ip_match)
                except Exception:
                    continue
    else:
        # fallback: só aplicar regex global se o texto indicar presença de IPs
        # keywords que sugerem que a linha contém endereços ou fontes de rede
        keywords = ['sample source ip', 'sample', 'src', 'dst', 'source ip', 'source', 'ip', 'from', 'to', 'destination']
        if any(k in s_lower for k in keywords) and len(s) < 4000:
            # extrair IPv4 explícitos com regex
            for ip_match in re.finditer(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s):
                ip = ip_match.group(0)
                try:
                    if all(0 <= int(p) <= 255 for p in ip.split('.')):
                        found.add(ip)
                except Exception:
                    continue
            # extrair tokens hex - ainda restrito a 8-32 chars
            for token in re.findall(r'\b(?:0x)?[0-9a-fA-F]{8,32}\b', s):
                if ip := convert_hex_like_to_ipv4(token):
                    found.add(ip)

    # retorno ordenado e deduplicado
    return sorted(found)





# ===============================
# Classificação por criticidade
# ===============================
def categorize_event(event_data):
    """
    Categoriza um evento com base em regras específicas e depois em termos gerais.
    Esta versão é robusta a variações nos nomes das colunas de veredito.
    """
    # Verificações de alta prioridade (se os dados forem de um CSV)
    if isinstance(event_data, dict):
        # REGRA 1: Procura o veredito em múltiplos nomes de coluna possíveis
        possible_keys = ['verdict', 'verbose_verdict', 'Verbose verdict']
        verdict_str = ""
        for key in possible_keys:
            if event_data.get(key):
                verdict_str = str(event_data.get(key)).lower()
                break  # Para no primeiro que encontrar

        # Agora, analisa o valor do veredito encontrado
        if verdict_str: # Se encontrou um valor em uma das colunas
            if verdict_str == 'mal':
                return "CRITICAL"
            if 'malware' in verdict_str:
                return "CRITICAL"
            if verdict_str == 'spm':
                return "WARNING"
            if 'spam' in verdict_str:
                return "WARNING"

    # REGRA 2: Fallback para termos gerais na linha inteira
    full_text = str(event_data).lower()
    
    critical_terms = ["malicious", "brute force", "bruteforce", "virus", "trojan", "attack", "breach", "locked out"]
    if any(term in full_text for term in critical_terms):
        return "CRITICAL"
        
    warning_terms = ["suspicious", "warn", "unusual", "adware", "premieropinion", "premier opinion", "pmservice", "pmservice.exe"]
    if any(term in full_text for term in warning_terms):
        return "WARNING"

    error_terms = ["error", "failed", "exception", "timeout", "err:5", "err: 11001"]
    if any(term in full_text for term in error_terms):
        return "ERROR"
        
    return "INFO"





# ===============================
# Threat Intelligence (batched/limit)
# ===============================
@st.cache_data(ttl=3600)
def query_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return None
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
                         params={'ipAddress': ip, 'maxAgeInDays': 90}, timeout=6)
        r.raise_for_status()
        return r.json().get('data', {})
    except Exception:
        return None

@st.cache_data(ttl=3600)
def query_virustotal_ip(ip):
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                         headers={'x-apikey': VIRUSTOTAL_API_KEY}, timeout=6)
        r.raise_for_status()
        return r.json().get('data', {}).get('attributes', {})
    except Exception:
        return None


# ===============================
# Módulo de Integração EDR (CrowdStrike)
# ===============================
# ATENÇÃO: Substitua pelas suas credenciais reais em um ambiente de produção
# É recomendado usar variáveis de ambiente ou um sistema de segredos.
CROWDSTRIKE_CLIENT_ID = "SEU_CLIENT_ID_AQUI"
CROWDSTRIKE_CLIENT_SECRET = "SEU_CLIENT_SECRET_AQUI"
CROWDSTRIKE_API_URL = "https://api.crowdstrike.com" # Usar a URL base correta para sua instância

def get_crowdstrike_token():
    """Obtém um token de autenticação da API do CrowdStrike."""
    url = f"{CROWDSTRIKE_API_URL}/oauth2/token"
    payload = {
        "client_id": CROWDSTRIKE_CLIENT_ID,
        "client_secret": CROWDSTRIKE_CLIENT_SECRET
    }
    response = requests.post(url, data=payload)
    response.raise_for_status()
    return response.json().get("access_token")

def contain_host_crowdstrike(host_aid, token):
    """
    Envia um comando para conter (isolar da rede) um host via API do CrowdStrike.
    'host_aid' é o Agent ID (AID) do host a ser contido.
    """
    if not all([CROWDSTRIKE_CLIENT_ID, CROWDSTRIKE_CLIENT_SECRET]) or "SEU_CLIENT_ID_AQUI" in CROWDSTRIKE_CLIENT_ID:
        return False, "Credenciais da API do CrowdStrike não configuradas no script."

    try:
        url = f"{CROWDSTRIKE_API_URL}/devices/actions/v1?action_name=contain"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        # O payload espera uma lista de IDs de host
        payload = {
            "ids": [host_aid]
        }
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()

        # A API retorna 202 (Accepted) e um corpo com detalhes da ação
        if response.status_code == 202 and not response.json().get('errors'):
            return True, f"Comando de contenção enviado com sucesso para o host {host_aid}."
        else:
            error_details = response.json().get('errors', [{}])[0].get('message', 'Erro desconhecido')
            return False, f"Falha ao conter o host {host_aid}: {error_details}"

    except requests.exceptions.RequestException as e:
        return False, f"Erro de comunicação com a API do CrowdStrike: {e}"
    except Exception as e:
        return False, f"Um erro inesperado ocorreu: {e}"

def check_stagent_health():
    """
    Verifica ativamente o status do serviço 'stAgentSvc' usando PowerShell.
    Retorna uma tupla (STATUS, MENSAGEM).
    STATUS pode ser: 'OK', 'WARNING', 'CRITICAL', 'ERROR'.
    """
    command = "Get-Service -Name 'stAgentSvc' | Select-Object Status, StartType | ConvertTo-Json"
    try:
        # trocamos text=True por encoding='cp850'
        # Isso corrige os caracteres com acentos vindos do console do Windows.
        result = subprocess.run(
            ["powershell", "-Command", command],
            capture_output=True,
            encoding='cp850', # Codificação para terminais Windows em português
            timeout=10,
            check=False
        )

        if result.stderr:
            # O PowerShell em português para este erro diz "Não é possível localizar"
            if "localizar qualquer servi" in result.stderr:
                return "ERROR", "O serviço 'stAgentSvc' não foi encontrado neste sistema."
            return "ERROR", f"Erro ao executar o comando PowerShell: {result.stderr}"

        # Analisa o JSON retornado pelo stdout
        service_info = json.loads(result.stdout)
        status = service_info.get("Status")
        start_type = service_info.get("StartType")

        if status == 4: # Running
            if start_type != "Automatic":
                 return "WARNING", f"O serviço está em execução, mas o tipo de inicialização é '{start_type}' (Recomendado: Automático)."
            return "OK", f"Serviço em execução (Status: Running, StartType: {start_type})."
        elif status == 1: # Stopped
            return "CRITICAL", f"O serviço está PARADO (Status: Stopped, StartType: {start_type}). Ações de remediação podem ser necessárias."
        else:
            return "WARNING", f"O serviço está em um estado inesperado (Status: {status}, StartType: {start_type})."

    except FileNotFoundError:
        return "ERROR", "Comando 'powershell' não encontrado. Verifique a instalação do PowerShell."
    except json.JSONDecodeError:
        return "ERROR", "Falha ao analisar a resposta do status do serviço. Resposta recebida: " + result.stdout
    except Exception as e:
        return "ERROR", f"Ocorreu um erro inesperado durante o Health Check: {e}"





# ===============================
# Extract timestamps (robusta)
# ===============================
def extract_timestamp(line):
    patterns = [
        r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})",
        r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
        r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})",
        r"(\d{4}/\d{2}/\d{2})",
        r"(\d{4}-\d{2}-\d{2})"
    ]
    for pattern in patterns:
        m = re.search(pattern, line)
        if m:
            s = m.group(1)
            for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y/%m/%d", "%Y-%m-%d"):
                try:
                    return datetime.strptime(s, fmt)
                except Exception:
                    continue
    return None





# ===============================
# Processamento de arquivos (usa preferências de colunas)
# ===============================
def process_uploaded_files(files):
    all_records = []
    full_text = ""
    all_scans = pd.DataFrame()
    all_detections = pd.DataFrame()

    for f in files:
        name = f.name.lower()
        content_bytes = f.read()
        try:
            if name.endswith('.csv'):
                try:
                    df_csv = pd.read_csv(io.StringIO(content_bytes.decode('utf-8')), dtype=str, low_memory=False)
                except UnicodeDecodeError:
                    df_csv = pd.read_csv(io.StringIO(content_bytes.decode('latin-1')), dtype=str, low_memory=False)
                df_csv['_source_file'] = f.name

                # Se existir coluna com IP de amostra, use-a preferencialmente para ip_list (decodificando se necessário)
                preferred_cols = [c for c in df_csv.columns if c.lower().strip() in ('sample source ip','sample source ip (ipv4)','sample_source_ip','sample_from','sample to','sample from')]
                for _, row in df_csv.iterrows():
                    row_dict = row.to_dict()
                    # prefer sample ip column
                    ip_list = []
                    if preferred_cols:
                        for pc in preferred_cols:
                            val = row_dict.get(pc)
                            if pd.notna(val) and val not in (None, ''):
                                # tenta converter direto (se for hex ou IPv4)
                                decoded = convert_hex_like_to_ipv4(val)
                                if decoded:
                                    ip_list.append(decoded)
                                else:
                                    # tentar extrair apenas do campo (mais conservador)
                                    ip_list.extend(extract_and_decode_ips(val))
                    # fallback: extrair apenas de campos relevantes do row_dict (não do row_str completo)
                    if not ip_list:
                        # converter row_dict em dict e extrair apenas de keys relevantes
                        for key, value in row_dict.items():
                            if value is None:
                                continue
                            key_l = str(key).lower()
                            if any(k in key_l for k in ('sample','source','ip','from','to','src','dst')):
                                ip_list.extend(extract_and_decode_ips(str(value)))
                    # garantias: dedupe por linha e limite quantidade razoável por linha (ex.: 50)
                    ip_list = sorted(set(ip_list))[:50]

                    # timestamp: tentar extrair de colunas comuns
                    ts = None
                    for col in df_csv.columns:
                        if 'date' in col.lower() or 'time' in col.lower() or 'created' in col.lower():
                            try:
                                ts = pd.to_datetime(row[col])
                                break
                            except Exception:
                                continue

                    all_records.append({
                        "timestamp": ts or None,
                        "raw": str(row_dict),
                        "category": categorize_event(row_dict),
                        "ip_list": ip_list,
                        "source_file": f.name
                    })

                # separa detections/scans heurística
                if "detection" in name or "detections" in name:
                    all_detections = pd.concat([all_detections, df_csv], ignore_index=True, sort=False)
                elif "scan" in name or "scans" in name:
                    all_scans = pd.concat([all_scans, df_csv], ignore_index=True, sort=False)

            else:
                try:
                    text = content_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    text = content_bytes.decode('latin-1', errors='replace')
                full_text += text + "\n"
                for line in text.splitlines():
                    if not line.strip():
                        continue
                    ts = extract_timestamp(line) or None
                    ips = extract_and_decode_ips(line)
                    # dedupe e limite por linha
                    ips = sorted(set(ips))[:50]
                    all_records.append({
                        "timestamp": ts,
                        "raw": line.strip(),
                        "category": categorize_event(line),
                        "ip_list": ips,
                        "source_file": f.name
                    })
        except Exception as e:
            st.error(f"Erro ao processar {f.name}: {e}")

    if not all_records:
        return pd.DataFrame(), full_text, all_scans, all_detections

    df = pd.DataFrame(all_records)
    # Esta linha única resolve os dois problemas: a mistura de fusos horários e o tipo da coluna.
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce').dt.tz_localize(None).fillna(pd.Timestamp.now(tz=None))

    # Correlação temporal simples
    df['correlated'] = False
    critical_idx = df[df['category'] == 'CRITICAL'].index
    for i in critical_idx:
        t = df.at[i, 'timestamp']
        window = df[(df['timestamp'] >= t - timedelta(minutes=60)) & (df['timestamp'] <= t + timedelta(minutes=60)) & (df.index != i)]
        if not window.empty:
            df.at[i, 'correlated'] = True
            df.loc[window.index, 'correlated'] = True

    return df, full_text, all_scans, all_detections





# ===============================
# Runbooks automatizados (permanecem como execução local)
# ===============================
def auto_remediation(action):
    try:
        if action == "premieropinion":
            commands = [
                "Stop-Service -Name 'PremierOpinion' -Force -ErrorAction SilentlyContinue",
                "sc.exe delete PremierOpinion",
                r"Remove-Item 'C:\Program Files\PremierOpinion' -Recurse -Force -ErrorAction SilentlyContinue"
            ]
        elif action == "stagent":
            commands = [
                "Restart-Service -Name 'stAgentSvc' -Force -ErrorAction SilentlyContinue",
                "Clear-DnsClientCache",
                "netsh winhttp reset proxy"
            ]
        else:
            return False, ["Ação não reconhecida"]
        results = []
        for cmd in commands:
            try:
                subprocess.run(["powershell", "-Command", cmd], timeout=40, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                results.append(f"✅ {cmd}")
            except Exception as e:
                results.append(f"❌ {cmd} -> {e}")
        return True, results
    except Exception as e:
        return False, [f"Erro: {e}"]





# ==========================================
# Estimativa de redução de falsos positivos
# ==========================================
def estimate_false_positive_reduction(df):
    """
    Calcula a redução de falsos positivos com base em novas regras de negócio.
    - Eventos CRITICAL (MAL) são considerados verdadeiros positivos e excluídos do cálculo.
    - O cálculo de redução é feito sobre o restante dos eventos (SPM, INFO, ERROR).
    """
    total_events = len(df)
    if total_events == 0:
        return {
            "total_events": 0, "true_positives": 0, "potential_fp_pool_size": 0,
            "correlated_in_pool": 0, "observed_reduction": 0, "estimated_by_poc": 0,
            "observed_pct": 0
        }

    # Verdadeiros positivos (CRITICAL/MAL) são separados e não fazem parte do pool de redução.
    true_positives_df = df[df['category'] == 'CRITICAL']
    true_positives_count = len(true_positives_df)

    # O "pool" de possíveis falsos positivos inclui tudo, EXCETO os críticos (ex: SPM, INFO, etc.).
    potential_fp_pool_df = df[df['category'] != 'CRITICAL']
    potential_fp_pool_size = len(potential_fp_pool_df)

    # A correlação valida eventos dentro deste pool, diminuindo o que precisa de análise.
    correlated_in_pool = int(potential_fp_pool_df['correlated'].sum())

    # A "redução observada" são os eventos não-críticos e não-correlacionados,
    # ou seja, o "ruído" que a correlação efetivamente filtrou.
    observed_reduction = potential_fp_pool_size - correlated_in_pool

    # A estimativa da PoC (~70%) agora é aplicada ao pool relevante.
    estimated_by_poc = int(potential_fp_pool_size * 0.7)
    
    observed_pct = (observed_reduction / potential_fp_pool_size * 100) if potential_fp_pool_size > 0 else 0

    return {
        "total_events": total_events,
        "true_positives": true_positives_count,
        "potential_fp_pool_size": potential_fp_pool_size,
        "correlated_in_pool": correlated_in_pool,
        "observed_reduction": observed_reduction,
        "estimated_by_poc": estimated_by_poc,
        "observed_pct": observed_pct
    }





# ===============================
# Interface principal
# ===============================
st.markdown("---")
uploaded = st.file_uploader("📂 Faça upload de arquivos (.csv, .txt, .log) — múltiplos permitidos", accept_multiple_files=True, type=['csv','txt','log'])

if uploaded:
    with st.spinner("🔄 Processando arquivos..."):
        df, full_text, all_scans, all_detections = process_uploaded_files(uploaded)

    if df.empty:
        st.warning("⚠️ Nenhum dado válido encontrado após processamento.")
    else:
        # Métricas
        total = len(df)
        critical = len(df[df['category'] == 'CRITICAL'])
        warnings = len(df[df['category'] == 'WARNING'])
        correlated = int(df['correlated'].sum())

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("📋 Total de eventos", total)
        c2.metric("🚨 Críticos", critical)
        c3.metric("⚠️ Avisos", warnings)
        c4.metric("🔗 Correlacionados", correlated)

        # Tabela
        st.subheader("📄 Eventos (amostra)")
        show_cols = ['timestamp', 'category', 'raw', 'ip_list', 'source_file', 'correlated']
        st.dataframe(df[show_cols].head(200))

        # Gráfico
        st.subheader("📈 Distribuição por Categoria")
        fig, ax = plt.subplots(figsize=(8, 4))
        counts = df['category'].value_counts()
        bars = ax.bar(counts.index, counts.values)
        ax.set_title("Eventos por Categoria")
        ax.set_ylabel("Contagem")
        st.pyplot(fig)

        st.markdown("---")
        st.subheader("🩺 Health Check do Agente")
        st.write("Verifica o status atual do serviço 'stAgentSvc' no sistema local.")

        if st.button("Verificar Saúde do Agente stAgentSvc"):
            with st.spinner("Verificando status do serviço..."):
                status_code, message = check_stagent_health()
                if status_code == "OK":
                    st.success(f"✅ **Status:** {status_code} | **Detalhes:** {message}")
                elif status_code in ["WARNING", "CRITICAL"]:
                    st.warning(f"⚠️ **Status:** {status_code} | **Detalhes:** {message}")
                else: # ERROR
                    st.error(f"❌ **Status:** {status_code} | **Detalhes:** {message}")


        # Runbooks
        st.subheader("🛠️ Runbooks Automáticos")
        colA, colB = st.columns(2)
        with colA:
            if st.button("🗑️ Remover PremierOpinion (runbook)"):
                ok, out = auto_remediation("premieropinion")
                if ok:
                    st.success("Comandos executados (ver resultados abaixo).")
                else:
                    st.error("Falha ao executar runbook.")
                for line in out:
                    st.write(line)
        with colB:
            if st.button("🔧 Corrigir stAgentSvc (runbook)"):
                ok, out = auto_remediation("stagent")
                if ok:
                    st.success("Comandos executados (ver resultados abaixo).")
                else:
                    st.error("Falha ao executar runbook.")
                for line in out:
                    st.write(line)

        st.markdown("---")
        st.subheader("🛡️ Runbooks de EDR (Simulação)")

        # Em um cenário real, o ID do host viria dos dados de log processados.
        # Para esta demonstração, usamos um campo de texto.
        host_id_to_contain = st.text_input("ID do Host (Agent ID) para Isolar", placeholder="Ex: 1234567890abcdef1234567890abcdef")

        if st.button("🚨 Isolar Host via CrowdStrike (Runbook)"):
            if host_id_to_contain:
                with st.spinner("Enviando comando de contenção para a API do EDR..."):
                    try:
                        # 1. Obter o token de autenticação
                        auth_token = get_crowdstrike_token()
                        if not auth_token:
                            st.error("Não foi possível obter o token de autenticação. Verifique as credenciais.")
                        else:
                            # 2. Executar a ação de contenção
                            ok, result = contain_host_crowdstrike(host_id_to_contain, auth_token)
                            if ok:
                                st.success(result)
                            else:
                                st.error(result)
                    except Exception as e:
                        st.error(f"Falha na execução do runbook de EDR: {e}")
            else:
                st.warning("Por favor, insira o ID do Host (Agent ID) para continuar.")

        # Estimativa de redução de falsos positivos
        st.markdown("---")
        st.subheader("📉 Estimativa de Redução de Falsos Positivos")
        est = estimate_false_positive_reduction(df)

        st.metric(label="Total de Eventos Analisados", value=est['total_events'])
        st.metric(label="Verdadeiros Positivos (Críticos/MAL)", value=est['true_positives'], help="Estes eventos são considerados ameaças reais e foram excluídos do cálculo de redução de ruído.")

        st.markdown("---")
        st.write(f"**Cálculo Baseado no Pool de Potenciais Falsos Positivos (SPM, INFO, etc.):**")

        c1, c2 = st.columns(2)
        c1.metric(label="Tamanho do Pool de Ruído", value=est['potential_fp_pool_size'])
        c2.metric(label="Eventos Validados por Correlação", value=est['correlated_in_pool'])

        st.metric(
            label="Redução de Ruído Observada (Não-Críticos e Não-Correlacionados)",
            value=f"{est['observed_reduction']} eventos",
            delta=f"{est['observed_pct']:.1f}% do pool",
            delta_color="off"
        )

        st.write(f"Redução Estimada pela PoC (~70% do Pool): **{est['estimated_by_poc']}** eventos")

        # Enriquecimento de IPs -> limitado por MAX_IPS_TO_QUERY (configurável)
        st.subheader("🌐 Enriquecimento Threat Intelligence (IPs únicos)")
        ips_log = set()
        for lst in df['ip_list'].dropna():
            if isinstance(lst, (list, tuple)):
                for ip in lst:
                    ips_log.add(ip)
            elif isinstance(lst, str) and lst:
                for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lst):
                    ips_log.add(ip)

        ips_all = sorted(ips_log)
        if ips_all:
            # aplicar limite configurável
            if MAX_IPS_TO_QUERY > 0:
                ips_to_query = ips_all[:MAX_IPS_TO_QUERY]
                st.write(f"IPs encontrados: {len(ips_all)} — consultando {len(ips_to_query)} (máx configurado: {MAX_IPS_TO_QUERY})")
            else:
                ips_to_query = []
                st.write(f"IPs encontrados: {len(ips_all)} — consultas desativadas (MAX_IPS_TO_QUERY=0)")

            ip_results = []
            for idx, ip in enumerate(ips_to_query, start=1):
                abuse = query_abuseipdb(ip) or {}
                vt = query_virustotal_ip(ip) or {}
                ip_results.append({
                    "IP": ip,
                    "AbuseScore": abuse.get('abuseConfidenceScore') if abuse else None,
                    "Country": abuse.get('countryCode') if abuse else None,
                    "VT_Malicious_Count": (vt.get('last_analysis_stats', {}).get('malicious') if vt else None)
                })
                # batching para evitar rate limits
                if (idx % BATCH_SIZE) == 0:
                    time.sleep(BATCH_SLEEP)

            if ip_results:
                st.dataframe(pd.DataFrame(ip_results))
        else:
            st.info("Nenhum IP identificado para consulta.")

        # Mapa (opcional)
        if FOLIUM_AVAILABLE and ips_all:
            st.subheader("🗺️ Mapa (GeoIP via ip-api.com — exemplo)")
            m = folium.Map(location=[0, 0], zoom_start=2)
            added = 0
            for ip in ips_all:
                try:
                    r = requests.get(f"http://ip-api.com/json/{ip}", timeout=4).json()
                    if r.get('status') == 'success' and 'lat' in r and 'lon' in r:
                        folium.Marker([r['lat'], r['lon']], popup=f"{ip} — {r.get('country')}").add_to(m)
                        added += 1
                except Exception:
                    continue
            if added:
                st_folium(m, width=700, height=400)
            else:
                st.info("GeoIP falhou ou não retornou localizações.")
        elif not FOLIUM_AVAILABLE:
            st.info("Folium/streamlit_folium não instalados — mapa desativado.")

else:
    st.info("📁 Faça upload de arquivos de logs (CSV/TXT) para iniciar a análise.")
    st.markdown("""
    Funcionalidades:
    - Leitura CSV/TXT com fallback de encoding
    - Decodificação HEX -> IPv4 (heurística mais conservadora)
    - Classificação automática de eventos
    - Correlação temporal simples (±60min)
    - Enriquecimento AbuseIPDB / VirusTotal (limitável)
    - Runbooks automáticos (execução local via PowerShell)
    - Métrica/estimativa de redução de falsos positivos
    """)
