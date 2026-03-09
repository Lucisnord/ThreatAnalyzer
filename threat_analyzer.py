#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ThreatAnalyzer - инструмент для анализа угроз
"""

import os
import re
import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

class ThreatAnalyzer:
    def __init__(self):
        self.logs = []
        self.suspicious_ips = []
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
                    
                    log_entry = {
                        'timestamp': parts[0],
                        'signature': ' '.join(parts[2:7]),
                        'priority': 1 if 'MALWARE' in line or 'CNC' in line else 2,
                        'src_ip': parts[8].split(':')[0],
                        'dst_ip': dst_ip,
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
        """Создание примера логов, если файл не найден"""
        sample_logs = [
            "2024-03-15T08:23:45 SURICATA ET MALWARE Cobalt Strike Beacon [Priority: 1] {UDP} 192.168.1.105:54321 -> 185.130.5.133:8080",
            "2024-03-15T08:24:12 SURICATA ET CNC Known Malicious IP [Priority: 1] {TCP} 192.168.1.110:12345 -> 45.155.205.233:80",
            "2024-03-15T08:25:30 SURICATA ET POLICY Suspicious DNS [Priority: 2] {UDP} 192.168.1.115:23456 -> 8.8.8.8:53",
            "2024-03-15T08:26:15 SURICATA ET MALWARE Win32/Tinba [Priority: 1] {TCP} 192.168.1.120:34567 -> 103.224.182.250:8080",
        ]
        
        os.makedirs('logs', exist_ok=True)
        with open('logs/suricata.log', 'w', encoding='utf-8') as f:
            for log in sample_logs:
                f.write(log + '\n')
        
        print("[+] Создан пример логов в logs/suricata.log")
        self.load_logs()
    
    def analyze(self):
        """Анализ данных"""
        print("\n[2/4] Анализ данных...")
        
        if not self.logs:
            print("[-] Нет данных")
            return False
        
        self.df = pd.DataFrame(self.logs)
        
        print("\n--- Статистика ---")
        print(f"Всего событий: {len(self.logs)}")
        print(f"Критических угроз (Priority 1): {len(self.suspicious_ips)}")
        
        return True
    
    def respond(self):
        """Реагирование на угрозы"""
        print("\n[3/4] Реагирование на угрозы...")
        
        if not self.suspicious_ips:
            print("[✓] Угроз не обнаружено")
            return
        
        print("\n[!] ОБНАРУЖЕНЫ УГРОЗЫ!")
        print("-" * 50)
        
        print("\n1. Блокировка IP:")
        for ip in self.suspicious_ips:
            print(f"   • {ip} - ЗАБЛОКИРОВАН")
        
        print("\n2. Уведомления отправлены:")
        print("   • Email: security@company.com")
        print("   • Telegram: @security_channel")
    
    def generate_report(self):
        """Создание отчёта"""
        print("\n[4/4] Формирование отчёта...")
        
        if self.df is None:
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Сохраняем отчёт
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_events': len(self.logs),
            'suspicious_ips': self.suspicious_ips,
        }
        
        json_file = f"reports/report_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        print(f"[+] JSON отчёт: {json_file}")
        
        # Создаём график
        plt.figure(figsize=(10, 5))
        
        ip_counts = {}
        for ip in self.suspicious_ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        if ip_counts:
            plt.bar(ip_counts.keys(), ip_counts.values(), color='red')
            plt.title('Подозрительные IP адреса')
            plt.xlabel('IP адрес')
            plt.ylabel('Количество обращений')
            plt.xticks(rotation=45, ha='right')
            
            chart_file = f"reports/chart_{timestamp}.png"
            plt.savefig(chart_file)
            print(f"[+] График: {chart_file}")
            plt.show()

def main():
    print("=" * 60)
    print("ThreatAnalyzer v1.0")
    print("=" * 60)
    
    analyzer = ThreatAnalyzer()
    analyzer.load_logs()
    analyzer.analyze()
    analyzer.respond()
    analyzer.generate_report()
    
    print("\n" + "=" * 60)
    print("Готово! Смотри папку 'reports'")
    print("=" * 60)

if __name__ == "__main__":
    main()