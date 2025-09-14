# Automation Script - Suspicious IP Blocking


## 목적
- 보안 관제 중 다량의 공격 트래픽이 유입되는 **악성 IP를 실시간 차단**
- SOC 분석가의 수동 차단 업무를 자동화하여 **탐지 → 대응 시간을 단축**


## 사용 도구
- Python
- Firewall REST API
- Threat Intelligence Feed (AbuseIPDB, VirusTotal)


## 스크립트 동작 흐름
1. SIEM(Splunk/ArcSight)에서 추출된 공격 원본 IP 리스트 입력
2. Threat Intelligence API와 연동하여 평판 조회(VirusTotal, AbuseIPDB)
3. 위험도가 일정 기준 이상이면 Firewall API 호출하여 정책에 차단 룰 추가
4. 차단 내역을 Slack/Webex Teams 등으로 알림 전송
