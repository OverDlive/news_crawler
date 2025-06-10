# SecBot – 일일 보안 크롤러 & 자동 방어기

**SecBot**은(는) Python 3.12 기반의 엔드투엔드 툴킷으로 다음 기능을 제공합니다.

* 보안뉴스 헤드라인, KISA 취약점 공지, 안랩 **ASEC** 블로그의 최신 IOC(IP / 해시 / URL) 정보 수집  
* Gmail(App Password 또는 XOAUTH2)을 통한 **일일 요약 메일** 발송  
* 수집된 악성 IP를 **ipset** 또는 **Suricata**에 즉시 반영하여 네트워크 선 차단  
* Dockerfile, systemd 서비스, pytest 테스트 수트 제공으로 손쉬운 CI/CD

---

## 폴더 구조

```text
.
├─ src/
│  ├─ secbot/                 ← 애플리케이션 패키지
│  │  ├─ fetchers/            ↳ news.py, advisory.py, asec.py
│  │  ├─ mailer/              ↳ gmail.py
│  │  ├─ defense/             ↳ ipset.py, suricata.py
│  │  ├─ utils/               ↳ logger.py, retry.py
│  │  ├─ config.py            ← 중앙 설정(Pydantic)
│  │  └─ main.py              ← 스케줄 루프 엔트리포인트
│  └─ tests/                  ← 오프라인 우선 테스트 수트(pytest)
├─ infra/                     ← Docker, systemd, K8s 매니페스트
└─ .env.sample                ← 복사 후 .env로 사용
```

---

## 빠른 시작(로컬 실행)

```bash
git clone https://github.com/handonghyeok/news_crawler.git
cd news_crawler
cp .env.sample .env          # SMTP·스케줄 옵션 수정

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # 또는 `pdm install`
python -m secbot.main
```

처음 실행하면 컬러 로그가 콘솔에 출력되고 테스트 메일이 전송됩니다.  
종료하려면 **Ctrl‑C**를 누르세요.

---

## Docker / Compose

```bash
docker compose up --build -d      # 컨테이너가 24/7 동작
docker compose logs -f secbot     # 실시간 로그 확인
```

`.env`에 지정한 환경 변수가 컨테이너에 자동 전달됩니다.

### 플랫폼별 Docker 명령어

macOS, Windows, Linux 환경에서 Docker 이미지를 직접 빌드하고 실행할 수 있습니다.

**macOS / Linux (bash/zsh)에서:**
```bash
# 이미지 빌드
docker build -t secbot-prod -f Dockerfile .
# .env 환경 변수로 컨테이너 한 번 실행
docker run --rm --env-file .env secbot-prod python -m secbot.main --once
# 백그라운드 모드로 실행
docker run -d --env-file .env --name secbot secbot-prod
```
**Windows PowerShell에서:**
```powershell
# 이미지 빌드
docker build -t secbot-prod -f Dockerfile .
# .env 환경 변수로 컨테이너 한 번 실행
docker run --rm --env-file .env secbot-prod python -m secbot.main --once
# 분리 모드로 실행
docker run -d --env-file .env --name secbot secbot-prod
```
**Windows CMD에서:**
```bat
:: 이미지 빌드
docker build -t secbot-prod -f Dockerfile .
:: .env 환경 변수로 컨테이너 한 번 실행
docker run --rm --env-file .env secbot-prod python -m secbot.main --once
:: 분리 모드로 실행
docker run -d --env-file .env --name secbot secbot-prod
```
---

## 설정(Environment Variables)

모든 옵션은 `.env` 파일 **또는** 쉘 환경 변수로 설정할 수 있습니다.

| 변수 | 기본값 | 설명 |
|------|--------|------|
|`SEC_BOT_CRON_TIME`|`06:00`|뉴스/공지 메일 시각 목록(HH:MM, 로컬)|
|`SEC_BOT_IOC_TIME`|`10:00`|하루 한 번 IOC 메일 및 차단 시각|
|`SEC_BOT_NEWS_LIMIT`|`10`|실행당 뉴스 헤드라인 개수(1‑50)|
|`SEC_BOT_ASEC_LIMIT`|`5`|ASEC 게시글 파싱 개수(1‑20)|
|`SEC_BOT_ENABLE_IPSET`|`true`|ipset 차단 활성화 여부|
|`SEC_BOT_ENABLE_SURICATA`|`false`|Suricata 룰 리로드 활성화 여부|

자세한 목록은 `.env.sample` 참조.

---

## 테스트 실행

```bash
pytest -m "not network"     # 오프라인 테스트만
pytest -m network           # 실시간 ASEC 스모크 테스트 포함
```

---

## 기여 방법

Pull Request 환영합니다! PR 제출 전 `pre‑commit run --all-files` 실행 및 `pytest` 통과를 확인해 주세요.

---

## 라이선스

본 프로젝트는 **MIT License**로 배포됩니다. 자세한 내용은 [LICENSE](LICENSE)를 참조하세요.