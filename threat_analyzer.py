#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ThreatAnalyzer - инструмент для анализа угроз информационной безопасности
"""

import os
import re
import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from collections import Counter

class ThreatAnalyzer:
    def __init__(self):
        self.logs = []
        self.suspicious_ips = []
        self.threats = []
        self.df = None
        
        # Создаём папки
        for folder in ['logs', 'reports']:
            if not os.path.exists(folder):
                os.makedirs(folder)
        
        print("[+] ThreatAnalyzer запущен")
    
    def load_logs(self, filename='logs/suricata.log'):
        """Загрузка логов"""
        print(f"\n[1/4] Загрузка логов из {filename}")
        
        if not os.path.exists(filename):
            print(f"[-] Файл {filename} не найден!")
            print("    Создаю пример логов...")
            self.create_sample_logs()
            return False
        
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                
                try:
                    dst_ip = parts[10].split(':')[0]
                    dst_port = parts[10].split(':')[1] if ':' in parts[10] else '0'
                    
                    log_entry = {
                        'timestamp': parts[0],
                        'signature': ' '.join(parts[2:7]),
                        'priority': 1 if 'MALWARE' in line or 'CNC' in line else 2,
                        'src_ip': parts[8].split(':')[0],
                        'src_port': parts[8].split(':')[1] if ':' in parts[8] else '0',
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                    }
                    self.logs.append(log_entry)
                    
                    if log_entry['priority'] == 1:
                        if dst_ip not in self.suspicious_ips:
                            self.suspicious_ips.append(dst_ip)
                except:
                    continue
        
        print(f"[+] Загружено {len(self.logs)} записей")
        print(f"[+] Найдено {len(self.suspicious_ips)} подозрительных IP")
        return True
    
    def create_sample_logs(self):
        """Создание примера логов"""
        sample_logs = [
            "2024-03-15T08:23:45 SURICATA ET MALWARE Cobalt Strike Beacon [Priority: 1] {UDP} 192.168.1.105:54321 -> 185.130.5.133:8080",
            "2024-03-15T08:24:12 SURICATA ET CNC Known Malicious IP [Priority: 1] {TCP} 192.168.1.110:12345 -> 45.155.205.233:80",
            "2024-03-15T08:25:30 SURICATA ET POLICY Suspicious DNS [Priority: 2] {UDP} 192.168.1.115:23456 -> 8.8.8.8:53",
            "2024-03-15T08:26:15 SURICATA ET MALWARE Win32/Tinba [Priority: 1] {TCP} 192.168.1.120:34567 -> 103.224.182.250:8080",
            "2024-03-15T08:27:42 SURICATA ET POLICY DNS Query [Priority: 2] {UDP} 192.168.1.125:45678 -> 8.8.8.8:53",
            "2024-03-15T08:28:55 SURICATA ET MALWARE Trickbot [Priority: 1] {TCP} 192.168.1.130:56789 -> 185.130.5.133:443",
        ]
        
        os.makedirs('logs', exist_ok=True)
        with open('logs/suricata.log', 'w', encoding='utf-8') as f:
            for log in sample_logs:
                f.write(log + '\n')
        
        print("[+] Создан пример логов в logs/suricata.log")
        self.load_logs()
    
    def analyze_dns(self):
        """БОНУС: Анализ DNS запросов (порт 53)"""
        print("\n--- Анализ DNS трафика ---")
        
        dns_queries = [log for log in self.logs if log.get('dst_port') == '53']
        
        if not dns_queries:
            print("  DNS запросов не обнаружено")
            return
        
        print(f"  Всего DNS запросов: {len(dns_queries)}")
        
        # Группировка по источникам
        sources = {}
        for query in dns_queries:
            src = query.get('src_ip', 'unknown')
            sources[src] = sources.get(src, 0) + 1
        
        print("  Топ источников DNS запросов:")
        for src, count in sorted(sources.items(), key=lambda x: x[1], reverse=True)[:3]:
            print(f"    • {src}: {count} запросов")
        
        # Проверка на аномалии (частые запросы)
        for src, count in sources.items():
            if count > 2:  # Больше 2 запросов - подозрительно
                print(f"  [!] Подозрительная активность DNS от {src} ({count} запросов)")
                self.threats.append({
                    'type': 'dns_anomaly',
                    'source': src,
                    'count': count,
                    'severity': 'MEDIUM'
                })
    
    def check_vulnerabilities(self):
        """БОНУС: Поиск уязвимостей с высоким CVSS"""
        print("\n--- Поиск известных уязвимостей ---")
        
        # Имитация базы уязвимостей
        vulnerabilities = [
            {"name": "CVE-2021-44228 (Log4Shell)", "cvss": 10.0, "description": "RCE в Log4j", "status": "CRITICAL"},
            {"name": "CVE-2021-41773 (Path Traversal)", "cvss": 7.5, "description": "Path traversal в Apache", "status": "HIGH"},
            {"name": "CVE-2022-22965 (Spring4Shell)", "cvss": 9.8, "description": "RCE в Spring Framework", "status": "CRITICAL"},
            {"name": "CVE-2020-1472 (Zerologon)", "cvss": 9.8, "description": "Privilege escalation в Windows", "status": "CRITICAL"},
            {"name": "CVE-2023-23397", "cvss": 8.8, "description": "RCE в Microsoft Office", "status": "HIGH"},
        ]
        
        found = 0
        for vuln in vulnerabilities:
            if vuln["cvss"] >= 7.0:  # Высокий и критический уровень
                print(f"  [!] {vuln['name']}")
                print(f"      CVSS: {vuln['cvss']} - {vuln['status']}")
                print(f"      Описание: {vuln['description']}")
                self.threats.append(vuln)
                found += 1
        
        print(f"\n  Найдено уязвимостей с CVSS >= 7.0: {found}")
    
    def analyze(self):
        """Анализ данных"""
        print("\n[2/4] Анализ данных...")
        
        if not self.logs:
            print("[-] Нет данных")
            return False
        
        self.df = pd.DataFrame(self.logs)
        
        # Основная статистика
        print("\n--- Основная статистика ---")
        print(f"  Всего событий: {len(self.logs)}")
        print(f"  Критических угроз (Priority 1): {len(self.suspicious_ips)}")
        
        # Бонусные анализы
        self.analyze_dns()
        self.check_vulnerabilities()
        
        return True
    
    def respond(self):
        """Реагирование на угрозы"""
        print("\n[3/4] Реагирование на угрозы...")
        
        if not self.suspicious_ips and not self.threats:
            print("[✓] Угроз не обнаружено")
            return
        
        print("\n[!] ОБНАРУЖЕНЫ УГРОЗЫ!")
        print("-" * 60)
        
        # Блокировка IP
        if self.suspicious_ips:
            print("\n1. Блокировка подозрительных IP:")
            for ip in set(self.suspicious_ips):
                print(f"   • {ip} - ЗАБЛОКИРОВАН")
                print(f"     iptables -A INPUT -s {ip} -j DROP")
        
        # Уведомления
        print("\n2. Отправка уведомлений:")
        print("   • Email: security@company.com")
        print(f"     Тема: Обнаружено {len(self.threats)} угроз")
        print("   • Telegram: @security_channel")
        print(f"     Сообщение: Заблокировано IP: {len(set(self.suspicious_ips))}, найдено уязвимостей: {len([t for t in self.threats if 'cvss' in t])}")
    
    def generate_report(self):
        """Создание отчёта"""
        print("\n[4/4] Формирование отчёта...")
        
        if self.df is None:
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Сохраняем JSON отчёт
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_events': len(self.logs),
            'suspicious_ips': list(set(self.suspicious_ips)),
            'threats': self.threats,
            'dns_stats': {
                'total_dns': len([l for l in self.logs if l.get('dst_port') == '53'])
            }
        }
        
        json_file = f"reports/report_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON отчёт: {json_file}")
        
        # Сохраняем CSV
        csv_file = f"reports/events_{timestamp}.csv"
        self.df.to_csv(csv_file, index=False)
        print(f"[+] CSV файл: {csv_file}")
        
        # Создаём график
        self.create_chart(timestamp)
    
    def create_chart(self, timestamp):
        """Создание графика"""
        plt.figure(figsize=(14, 6))
        
        # График 1: Подозрительные IP
        plt.subplot(1, 2, 1)
        ip_counts = {}
        for ip in self.suspicious_ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        if ip_counts:
            ips = list(ip_counts.keys())
            counts = list(ip_counts.values())
            colors = ['red'] * len(ips)
            plt.bar(ips, counts, color=colors)
            plt.title('Подозрительные IP адреса', fontsize=14, fontweight='bold')
            plt.xlabel('IP адрес')
            plt.ylabel('Количество обращений')
            plt.xticks(rotation=45, ha='right')
        
        # График 2: Уязвимости по CVSS
        plt.subplot(1, 2, 2)
        vulns = [t for t in self.threats if 'cvss' in t]
        if vulns:
            names = [v['name'][:20] + '...' for v in vulns]
            cvss = [v['cvss'] for v in vulns]
            colors = ['darkred' if c >= 9 else 'red' if c >= 7 else 'orange' for c in cvss]
            plt.barh(names, cvss, color=colors)
            plt.title('Уязвимости по CVSS баллам', fontsize=14, fontweight='bold')
            plt.xlabel('CVSS балл')
            plt.xlim(0, 10)
        
        plt.tight_layout()
        
        chart_file = f"reports/chart_{timestamp}.png"
        plt.savefig(chart_file, dpi=100, bbox_inches='tight')
        print(f"[+] График: {chart_file}")
        plt.show()

def main():
    print("=" * 70)
    print("ThreatAnalyzer v2.0 - Инструмент анализа угроз ИБ")
    print("=" * 70)
    
    analyzer = ThreatAnalyzer()
    analyzer.load_logs()
    analyzer.analyze()
    analyzer.respond()
    analyzer.generate_report()
    
    print("\n" + "=" * 70)
    print("✅ Анализ завершен! Результаты в папке 'reports'")
    print("=" * 70)

if __name__ == "__main__":
    main()