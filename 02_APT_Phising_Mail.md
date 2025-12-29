## APT 피싱 메일 훈련

목적
-

APT 모의훈련을 통한 임직원 보안 인식 제고 및 탐지 체계 검증

시나리오
-

1. 지능형 지속 위협(APT) 메일을 외부에서 내부 사용자 대상으로 메일 발송
2. 이를 탐지하기 위한 NDR 룰 생성 ex) 악성 메일 내 피싱사이트 클릭 시 이벤트 발생, 피싱사이트 내 계정 정보 입력 시 이벤트 발생, 해킹메일 신고 시 이벤트 발생
3. 훈련 내용을 한 눈에 볼 수 있게 SIEM 장비에서 시각화



#### 1. 피싱 메일 발송


계정 정보 입력 페이지를 모방하여 피싱 사이트를 만들어 메일 발송

메일 발송과정에서 From 부분 내부 admin 계정이 발송한 것처럼 변조

내부 사용자가 열 수 밖에 없는 메일들로 위장 ex) 연말 성과급 지급

<img width="391" height="811" alt="image" src="https://github.com/user-attachments/assets/81898c81-8554-4929-846f-a1548f00933a" />

주의사항
-

- 피싱메일 발송 과정에서 From 변조시 내부 도메인으로 변조할 경우 SPF/DKIM/DMARC 정책에 의해 차단될 확률이 높아 화이트리스트 처리 필요


#### 2. NDR 룰 생성

메일 열람 
-
ex) content:admin@admin.com

메일 열람의 경우 content 내 모의해킹 송신자 주소가 포함될 경우를 탐지하여 이벤트 발생

링크 클릭
-

ex) content:phishing.php?id=

링크 클릭하여 피싱 사이트 접근의 경우 피싱 사이트 주소 접근 시 이벤트 발생

임의 정보 입력 
-

ex) content:login_phishing.php?email=

정보 입력의 경우 피싱 사이트 로그인 페이지로 값 입력 시 이벤트 발생

실제 계정 정보 입력
-

ex) content:aptPhishing.php

실제 계정 정보 입력의 경우 임의 정보 입력과는 아래와 같이 다른 페이지가 뜨게하여 예시 페이지에 접근 시 이벤트 발생

<img width="579" height="749" alt="image" src="https://github.com/user-attachments/assets/1ee37456-f5dd-4de0-8873-a65e8fdd2aa9" />

해킹 메일 신고 
-
ex) content:/report.json content:report

해킹 메일 신고의 경우 신고 페이지 접근 및 발송 시 이벤트 발생하여 해킹 메일 신고 시 이벤트 발생



시각화
-

- Splunk를 활용한 대시보드로 한 눈에 내부 사용자 대처 레벨 확인 가능

```
ex) index=NDR msg=20250000_NDR_APT* 
|sort DATE
| eval OPEN=case(msg=="20250000_NDR_APT_Email_OPEN","o")
| eval LinkClick=case(msg=="20250000_NDR_APT_Email_LinkClick","o")
| eval DataInput=case(msg=="20250000_NDR_APT_Email_DataInput","o")
| eval realData=case(msg=="20250000_NDR_APT_Email_realData","o")
| eval report=case(msg=="20250000_NDR_APT_Email_report","o")
| join type=outer IP [ search index=real_IP 
| eval IP=mvindex(split(field,","),0)
| eval NAME=mvindex(split(field,","),1)
| eval ID=mvindex(split(field,","),2)
| dedup ID
| table ID, NAME, IP
] 
stats first(DATE) as "열람시간" values(OPEN) as "열람여부" values(LinkClick) as "링크접속" values(DataInput) as "데이터입력" values(realData) as "실제계정입력" values(report) as "해킹메일신고" by ID NAME IP
```

사진 출처 

https://www.fnnews.com/news/202512170739271071
