# Automation Script - Suspicious IP Blocking


## 목적
- 보안 관제 중 다량의 공격 트래픽이 유입되는 **악성 IP를 실시간 차단**
- SOC 분석가의 수동 차단 업무를 자동화하여 **탐지 → 대응 시간을 단축**


## 사용 도구
- Python
- Firewall REST API
- Threat Intelligence Feed (AbuseIPDB, VirusTotal) API


## 스크립트 동작 흐름
1. SIEM(Splunk/ArcSight)에서 추출된 공격 원본 IP 리스트 입력
2. Threat Intelligence API와 연동하여 평판 조회(VirusTotal, AbuseIPDB)
3. 위험도가 일정 기준 이상이면 Firewall API 호출하여 정책에 차단 룰 추가
4. 차단 내역을 Slack/Webex Teams 등으로 알림 전송


## 코드 (python)

``` python

import requests
import json
import os

# env에서 키값 가져오기(외부노출 방지)
Virustotal_key = os.getenv("Virustotal_key")
AbuseIPDB_key = os.getenv("AbuseIPDB_key")

# VirusTotal IP 평판 조회 함수
def Vcheck_ip_reputation(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey":Virustotal_key}
    response = requests.get(url , headers = headers)
    return response.json()

#AbuseIPDB IP 평판 조회 함수
def Acheck_ip_reputation(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": AbuseIPDB_key}
    response = requests.get(url, headers=headers)
    return response.json()


# 실행
suspicious_ip = ["103.140.1.71"]

for ip in suspicious_ip:
    reputation1 = Vcheck_ip_reputation(ip)
    reputation2 = Acheck_ip_reputation(ip)
    
    virustotal_Score = reputation1["data"]["attributes"]["total_votes"]["malicious"]
    abuse_Score = reputation2["data"]["abuseConfidenceScore"]
    
    
    if virustotal_Score > 50 or abuse_Score > 50:
        print("악성")
        


# IP 평판조회결과 score만 가져오기
print(f"virustotal:{reputation1["data"]["attributes"]["total_votes"]["malicious"]}")    
print(f"abuseIPdb:{reputation2["data"]["abuseConfidenceScore"]}")


    


```
