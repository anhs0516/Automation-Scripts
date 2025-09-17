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
import subprocess

# env에서 키값 가져오기(외부노출 방지)
Virustotal_key = os.getenv("Virustotal_key")
AbuseIPDB_key = os.getenv("AbuseIPDB_key")


#텍스트 파일 내 평판조회할 IP 읽어오기
def ip_list(file):
    # 한 줄 씩 읽어서 리스트형식으로 반환
    iplist =[]
    try:
        with open(file , 'r') as f:
            for line in f:
                # 앞뒤 공백제거, 빈 줄 제거
                ip = line.strip()
                if ip:
                    iplist.append(ip)
            print(iplist)
    except FileNotFoundError:
        print(f"Error{file} 파일을 찾을 수 없습니다.")
        return None
    return iplist
        


# VirusTotal IP 평판 조회 함수
def Vcheck_ip_reputation(ip):
    try:    
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey":Virustotal_key}
        response = requests.get(url , headers = headers)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal API 호출 실패 : {e}")
    except KeyError:
        print("Virustotal 응답 데이터 형식이 올바르지 않습니다.")
    return 0

#AbuseIPDB IP 평판 조회 함수
def Acheck_ip_reputation(ip):
    try:    
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {"Key": AbuseIPDB_key}
        response = requests.get(url, headers=headers)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"AbuseIPDB API 호출 실패 : {e}")
    except KeyError:
        print("AbuseIPDB 응답 데이터 형식이 올바르지 않습니다.")
    return 0



# UFW(Uncomplicated Firewall) 방화벽 차단(리눅스 시스템, 방화벽 설정을 쉽게 관리하기 위한 도구)
def block_ip_ufw(ip):
    try:
        # 리스트형태로 제공하면 각 단어를 별도의 인자로 취급하여 보안상 위험한 인젝션 공격등을 방지할 수 있음
        command = ["sudo", "ufw", "deny", "from", ip]
        # subprocess.run 파이썬 스크립트 안에서 리눅스 명령어 실행 및 결과받아오기
        # capture_output : 실행 결과 캡쳐 여부 결정, 표준 출력과 표준 에러를 파이썬 변수로 받아올 수 있음
        # check : 오류 발생 시 예외 발생 여부를 결정합니다. 실행 실패를 명확히 알 수 있음
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"IP: {ip} ufw 방화벽 차단 성공: {result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"ufw 방화벽 차단 실패 : {e.stderr}")


# 실행
if __name__ == "__main__":
    
    suspicious_ip = []
    suspicious_ip = ip_list("suspicious_ip.txt")

    for ip in suspicious_ip:
        reputation1 = Vcheck_ip_reputation(ip)
        reputation2 = Acheck_ip_reputation(ip)
        
        virustotal_Score = reputation1["data"]["attributes"]["total_votes"]["malicious"]
        abuse_Score = reputation2["data"]["abuseConfidenceScore"]
        
        
        if virustotal_Score > 50 or abuse_Score > 50:
            print(f"해당 {ip}평판 조회 결과 악성으로 IP 방화벽 차단합니다.")
            block_ip_ufw(ip)
            


    # IP 평판조회결과 score만 가져오기
        print(f"virustotal:{reputation1["data"]["attributes"]["total_votes"]["malicious"]}")    
        print(f"abuseIPdb:{reputation2["data"]["abuseConfidenceScore"]}")





    


```
