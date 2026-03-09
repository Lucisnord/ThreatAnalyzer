# ThreatAnalyzer

Инструмент для анализа угроз информационной безопасности на Python.

## Возможности
- Анализ логов Suricata
- Выявление подозрительных IP
- Мониторинг DNS-трафика
- Поиск уязвимостей (CVSS)
- Блокировка угроз (имитация)
- Отчёты JSON, CSV и графики PNG

## Подготовка и запуск
git clone
cd ThreatAnalyzer
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
python threat_analyzer.py