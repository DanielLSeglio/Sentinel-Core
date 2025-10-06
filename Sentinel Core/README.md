# 🛡️ SENTINEL-CORE

**SENTINEL-CORE** é uma plataforma de orquestração de segurança (SOC) desenvolvida como parte do **Challenge FIAP 2025**, realizado para a **DFENSE Security**.

O projeto automatiza a triagem de eventos, a correlação temporal de ataques e a resposta a incidentes, integrando APIs de Threat Intelligence e runbooks de remediação.

---

## 🚀 Funcionalidades

- Triagem inteligente e categorização de eventos (CRITICAL, WARNING, INFO)
- Correlação temporal de alertas e detecção de campanhas coordenadas
- Integração com APIs de Threat Intelligence (**VirusTotal**, **AbuseIPDB**)
- Dashboard interativo em **Streamlit**
- Runbooks automatizados de resposta via **PowerShell** (PremierOpinion, stAgentSvc)
- Preparação para integração com **CrowdStrike EDR** e **Elastic SIEM**
- Estimativa de redução de falsos positivos (~70%)

---

## 🧰 Tecnologias Utilizadas

- **Python 3.11+**
- **Streamlit**
- **Pandas**
- **Requests**
- **Matplotlib**
- **Folium / Streamlit-Folium**
- **PowerShell (execução local de runbooks)**

---

## 🧩 Estrutura do Projeto

```
sentinel-core/
│
├── sentinel_core.py      # Código principal do dashboard
├── requirements.txt      # Dependências do projeto
└── README.md             # Documentação
```

---

## 🖥️ Execução Local

```bash
pip install -r requirements.txt
python -m streamlit run sentinel_core.py
```

---

## 👥 Autores

Desenvolvido por:
- **Daniel Seglio**
- **Gustavo Nascimento**
- **João Guilherme**
- **Felipe Farias**
- **Renato Farias**

---

## 🏫 Challenge FIAP 2025 — DFENSE Security

Projeto desenvolvido como parte do **Challenge FIAP – Cyber Security 2025**, com foco em análise de logs, resposta a incidentes e automação de segurança corporativa.
