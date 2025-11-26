# DHCPv6 Tester

완전한 기능을 갖춘 DHCPv6 클라이언트 및 서버 시뮬레이터 with 실시간 대시보드

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![RFC 8415](https://img.shields.io/badge/RFC-8415-orange.svg)](https://tools.ietf.org/html/rfc8415)

## 📋 목차

- [개요](#개요)
- [주요 기능](#주요-기능)
- [설치](#설치)
- [빠른 시작](#빠른-시작)
- [사용 방법](#사용-방법)
  - [DHCPv6 클라이언트](#dhcpv6-클라이언트)
  - [DHCPv6 서버](#dhcpv6-서버)
  - [클라이언트-서버 테스트](#클라이언트-서버-테스트)
- [실시간 대시보드](#실시간-대시보드)
- [아키텍처](#아키텍처)
- [CLI 옵션](#cli-옵션)
- [고급 기능](#고급-기능)
- [예제 시나리오](#예제-시나리오)
- [트러블슈팅](#트러블슈팅)
- [RFC 8415 준수](#rfc-8415-준수)

---

## 개요

DHCPv6 Tester는 DHCPv6 프로토콜의 클라이언트와 서버를 시뮬레이션하는 도구입니다. 네트워크 테스트, DHCPv6 서버 검증, 부하 테스트 등에 사용할 수 있습니다.

### 왜 이 도구를 사용하나요?

- 🧪 **DHCPv6 서버 테스트**: 실제 클라이언트 없이 서버 동작 검증
- 📊 **부하 테스트**: 수백 개의 클라이언트 동시 시뮬레이션
- 🔍 **프로토콜 학습**: DHCPv6 메시지 흐름 실시간 모니터링
- 🌐 **Relay Agent 테스트**: RELAY-FORW/RELAY-REPL 메시지 지원
- 📈 **실시간 대시보드**: 클라이언트 상태 및 통계 시각화

---

## 주요 기능

### DHCPv6 클라이언트 시뮬레이터

- ✅ **기본 주소 할당** (SOLICIT → ADVERTISE → REQUEST → REPLY)
- ✅ **Prefix Delegation** (DHCPv6-PD)
- ✅ **다중 클라이언트** (1~1000+ 동시 시뮬레이션)
- ✅ **Renew/Rebind** (T1/T2 타이머 기반 자동 갱신)
- ✅ **RFC 8415 재전송** (Exponential backoff, 최대 재시도)
- ✅ **Relay Agent 모드** (RELAY-FORW 전송)
- ✅ **실시간 대시보드** (Rich 기반 TUI)

### DHCPv6 서버 시뮬레이터

- ✅ **주소 풀 관리** (CIDR 기반 자동 할당)
- ✅ **Prefix Delegation 풀** (사용자 정의 prefix 길이)
- ✅ **SOLICIT → ADVERTISE**
- ✅ **REQUEST → REPLY** (주소 할당 확정)
- ✅ **RENEW/REBIND → REPLY** (Lease 갱신)
- ✅ **Relay Agent 지원** (RELAY-FORW 처리)
- ✅ **Lease 추적** (클라이언트별 할당 관리)
- ✅ **통계 및 로깅**

### 프로토콜 기능

| 기능 | 클라이언트 | 서버 | 설명 |
|------|-----------|------|------|
| Basic Address Allocation | ✅ | ✅ | IA_NA (Non-temporary Address) |
| Prefix Delegation | ✅ | ✅ | IA_PD (DHCPv6-PD) |
| Renew | ✅ | ✅ | T1 기반 갱신 |
| Rebind | ✅ | ✅ | T2 기반 재바인딩 |
| Relay Agent | ✅ | ✅ | RELAY-FORW/RELAY-REPL |
| Retransmission | ✅ | - | RFC 8415 Exponential backoff |
| Multicast | ✅ | ✅ | ff02::1:2 |
| Unicast (Relay) | ✅ | ✅ | 서버 직접 통신 |

---

## 설치

### 요구사항

- **OS**: Linux (권장), macOS
- **Python**: 3.7 이상
- **권한**: root/sudo (raw socket 접근)
- **네트워크**: IPv6 활성화된 인터페이스

### 의존성 설치

```bash
# 저장소 클론
git clone <repository-url>
cd dhcpv6-tester

# Python 패키지 설치
pip install -r requirements.txt

# libpcap 설치 (선택사항, 패킷 캡처 성능 향상)
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel

# macOS
brew install libpcap
```

### requirements.txt

```
scapy>=2.5.0
netifaces>=0.11.0
rich>=13.0.0
```

---

## 빠른 시작

### 1. 클라이언트만 실행 (외부 DHCPv6 서버 테스트)

```bash
sudo python3 dhcpv6_simulator.py --interface eth0
```

### 2. 클라이언트 + 서버 동시 실행

**터미널 1 - 서버 시작:**
```bash
sudo python3 dhcpv6_server_simulator.py --interface eth0
```

**터미널 2 - 클라이언트 시작:**
```bash
sudo python3 dhcpv6_simulator.py --interface eth0 --clients 5 --prefix-delegation
```

### 3. Relay 모드 테스트

```bash
# 서버에 직접 유니캐스트 (Relay Agent 시뮬레이션)
sudo python3 dhcpv6_simulator.py \
  --interface eth0 \
  --relay-server fe80::1 \
  --clients 10
```

---

## 사용 방법

### DHCPv6 클라이언트

#### 기본 사용 (실시간 대시보드)

```bash
# 단일 클라이언트
sudo python3 dhcpv6_simulator.py --interface eth0

# 10개 클라이언트 동시 실행
sudo python3 dhcpv6_simulator.py --interface eth0 --clients 10

# Prefix Delegation 요청
sudo python3 dhcpv6_simulator.py --interface eth0 --prefix-delegation

# Renew/Rebind 테스트 (T1/T2 타이머)
sudo python3 dhcpv6_simulator.py --interface eth0 --renew --duration 180

# 모든 기능 활성화
sudo python3 dhcpv6_simulator.py \
  --interface eth0 \
  --clients 50 \
  --prefix-delegation \
  --renew \
  --duration 300
```

#### 로그 모드 (대시보드 없이)

```bash
# 디버깅/로그 수집용
sudo python3 dhcpv6_simulator.py \
  --interface eth0 \
  --clients 100 \
  --no-dashboard \
  --verbose
```

#### Relay 모드

```bash
# DHCPv6 서버에 직접 유니캐스트
sudo python3 dhcpv6_simulator.py \
  --interface eth0 \
  --relay-server fe80::1:2:3:4 \
  --relay-address fe80::5:6:7:8 \
  --clients 20
```

### DHCPv6 서버

#### 기본 서버 실행

```bash
# 기본 주소/Prefix 풀
sudo python3 dhcpv6_server_simulator.py --interface eth0
```

#### 주소 풀 커스터마이징

```bash
sudo python3 dhcpv6_server_simulator.py \
  --interface eth0 \
  --address-pool 2001:db8:1000::/64 \
  --prefix-pool 2001:db8:2000::/48 \
  --prefix-length 56
```

#### Lifetime 설정

```bash
sudo python3 dhcpv6_server_simulator.py \
  --interface eth0 \
  --valid-lifetime 3600 \
  --preferred-lifetime 1800 \
  --stats-interval 10
```

### 클라이언트-서버 테스트

**시나리오: 100개 클라이언트 부하 테스트**

```bash
# 터미널 1: 서버 (통계 10초마다 출력)
sudo python3 dhcpv6_server_simulator.py \
  --interface eth0 \
  --address-pool 2001:db8::/64 \
  --prefix-pool 2001:db8:1::/48 \
  --stats-interval 10 \
  --verbose

# 터미널 2: 클라이언트 (대시보드 모드)
sudo python3 dhcpv6_simulator.py \
  --interface eth0 \
  --clients 100 \
  --prefix-delegation \
  --renew \
  --duration 600
```

---

## 실시간 대시보드

클라이언트 시뮬레이터는 기본적으로 실시간 대시보드 모드로 실행됩니다.

### 대시보드 구성

```
┌─────────────────────────────────────────────────────────────────┐
│ DHCPv6 Client Simulator [Relay Mode] | Interface: eth0 |       │
│ Running: 45s / 60s | Remaining: 15s                            │
└─────────────────────────────────────────────────────────────────┘

┌─ Client Status ──────────────┬─ Statistics ─────────────┐
│ ID       │ State  │ IPv6     │ Total Clients       10   │
├──────────┼────────┼──────────┤                          │
│ client-1 │ ✅ BOUND│ 2001:db8│ Mode             Relay   │
│ client-2 │ 📤 SOLICIT│ -     │ Server        fe80::1    │
│ client-3 │ 📨 REQUEST│ -     │                          │
│ ...      │ ...    │ ...     │ ⚪ INIT              2   │
│                              │ 📤 SOLICIT           3   │
│                              │ 📨 REQUEST           2   │
│                              │ ✅ BOUND             3   │
│                              │                          │
│                              │ Addresses            3   │
│                              │ Prefixes             3   │
│                              │                          │
│                              │ Success Rate      30.0%  │
└──────────────────────────────┴──────────────────────────┘

┌─ Recent Events ──────────────────────────────────────────┐
│ ✅ client-1: BOUND -> 2001:db8:1::1                      │
│ 📤 client-2: SOLICIT                                     │
│ 📨 client-3: REQUEST                                     │
│                                                          │
│ Press Ctrl+C to stop                                     │
└──────────────────────────────────────────────────────────┘
```

### 상태 아이콘

| 아이콘 | 상태 | 설명 |
|--------|------|------|
| ⚪ | INIT | 초기화 |
| 📤 | SOLICIT | SOLICIT 전송 → ADVERTISE 대기 |
| 📨 | REQUEST | REQUEST 전송 → REPLY 대기 |
| ✅ | BOUND | 주소/Prefix 할당 완료 |
| 🔄 | RENEW | RENEW 메시지 전송 (T1 갱신) |
| ⚠️ | REBIND | REBIND 메시지 전송 (T2 재바인딩) |

---

## 아키텍처

### 프로젝트 구조

```
dhcpv6-tester/
├── dhcpv6_packet.py           # DHCPv6 패킷 빌더/파서
├── dhcpv6_client.py           # 클라이언트 상태 머신
├── dhcpv6_server.py           # 서버 상태 머신
├── dhcpv6_simulator.py        # 클라이언트 시뮬레이터 실행
├── dhcpv6_server_simulator.py # 서버 시뮬레이터 실행
├── dashboard.py               # 실시간 대시보드 UI
├── CLAUDE.md                  # 개발자 문서
├── README.md                  # 이 파일
└── requirements.txt           # Python 의존성
```

### 레이어 아키텍처

```
┌─────────────────────────────────────────────────────────┐
│                  Application Layer                      │
│  dhcpv6_simulator.py / dhcpv6_server_simulator.py      │
│  (멀티 클라이언트/서버 오케스트레이션, asyncio)           │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│              State Machine Layer                        │
│     dhcpv6_client.py / dhcpv6_server.py                │
│  (상태 관리, 타이머, 스레드, 재전송 로직)                  │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│              Packet Layer                               │
│              dhcpv6_packet.py                           │
│  (DHCPv6 메시지 생성/파싱, Scapy)                        │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│              Network Layer                              │
│        Scapy (sendp, sniff) + Raw Socket               │
└─────────────────────────────────────────────────────────┘
```

### 클라이언트 상태 머신 (RFC 8415)

```
     INIT
       │
       ▼
   SOLICIT ────────► (재전송: 1s, 2s, 4s, 8s, ...)
       │
       │ ADVERTISE
       ▼
   REQUEST ────────► (재전송: 1s, 2s, 4s, 최대 10회)
       │
       │ REPLY
       ▼
     BOUND
       │
       ├─────► (T1 만료) ────► RENEW ────► REPLY ────► BOUND
       │
       └─────► (T2 만료) ────► REBIND ───► REPLY ────► BOUND
```

### 서버 처리 흐름

```
  클라이언트                    서버
      │                          │
      │─────── SOLICIT ─────────►│
      │                          │ (주소/Prefix 할당)
      │◄────── ADVERTISE ────────│
      │                          │
      │─────── REQUEST ─────────►│
      │                          │ (Lease 확정)
      │◄─────── REPLY ───────────│
      │                          │
   (BOUND)                       │
      │                          │
      │─────── RENEW ───────────►│ (T1 시점)
      │◄─────── REPLY ───────────│
      │                          │
```

---

## CLI 옵션

### 클라이언트 (dhcpv6_simulator.py)

| 옵션 | 단축 | 기본값 | 설명 |
|------|------|--------|------|
| `--interface` | `-i` | (필수) | 네트워크 인터페이스 이름 |
| `--clients` | `-c` | 1 | 시뮬레이션할 클라이언트 수 |
| `--prefix-delegation` | `-p` | False | Prefix Delegation 요청 |
| `--duration` | `-d` | 60 | 실행 시간 (초) |
| `--renew` | | False | Renew/Rebind 테스트 활성화 |
| `--no-dashboard` | | False | 대시보드 비활성화 (로그 모드) |
| `--relay-server` | | None | Relay 모드: 서버 IPv6 주소 |
| `--relay-address` | | None | Relay 모드: Relay Agent 주소 |
| `--verbose` | `-v` | False | 상세 로그 출력 |

### 서버 (dhcpv6_server_simulator.py)

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--interface` | (필수) | 네트워크 인터페이스 이름 |
| `--address-pool` | 2001:db8:1::/64 | IPv6 주소 풀 (CIDR) |
| `--prefix-pool` | 2001:db8:2::/48 | Prefix Delegation 풀 (CIDR) |
| `--prefix-length` | 56 | 위임할 Prefix 길이 |
| `--valid-lifetime` | 7200 | Valid lifetime (초) |
| `--preferred-lifetime` | 3600 | Preferred lifetime (초) |
| `--stats-interval` | 30 | 통계 출력 간격 (초, 0=비활성화) |
| `--verbose` | False | 상세 로그 출력 |

---

## 고급 기능

### RFC 8415 재전송 로직

클라이언트는 RFC 8415에 따른 Exponential Backoff 알고리즘을 사용합니다:

**SOLICIT 재전송:**
- IRT (Initial Retransmission Time): 1초
- MRT (Maximum Retransmission Time): 3600초
- 재시도: 무제한 (서버를 찾을 때까지)

**REQUEST 재전송:**
- IRT: 1초
- MRT: 30초
- 재시도: 최대 10회 (실패 시 SOLICIT으로 복귀)

**재전송 간격 계산:**
```python
RT = 2 * RTprev + RAND * RTprev
# RAND: -0.1 ~ +0.1 (네트워크 충돌 방지)
# RT > MRT이면 RT = MRT + RAND * MRT
```

**예시:**
- 1차: 1초 후
- 2차: ~2초 후 (누적 3초)
- 3차: ~4초 후 (누적 7초)
- 4차: ~8초 후 (누적 15초)
- 5차: ~16초 후 (누적 31초)
- 6차~: 30초 간격 (MRT 도달)

### Relay Agent 모드

Relay Agent는 클라이언트와 서버가 다른 네트워크에 있을 때 사용됩니다:

```bash
# 클라이언트: Relay Agent로 동작
sudo python3 dhcpv6_simulator.py \
  --interface eth0 \
  --relay-server 2001:db8::1 \
  --relay-address fe80::1234 \
  --clients 10

# 메시지 흐름:
# 1. 클라이언트 메시지 (SOLICIT, REQUEST)
# 2. RELAY-FORW로 감싸기 (hop-count, link-address, peer-address 포함)
# 3. 서버로 유니캐스트 전송
# 4. 서버가 RELAY-REPL로 응답
# 5. 원본 메시지 추출하여 클라이언트 처리
```

### 멀티스레드 아키텍처

각 클라이언트는 독립적인 스레드에서 동작:

- **메인 스레드**: asyncio 이벤트 루프
- **클라이언트별 스레드**: 패킷 수신 (sniff)
- **타이머 스레드**: 재전송, Renew, Rebind (threading.Timer)
- **대시보드 스레드**: Rich Live 업데이트

---

## 예제 시나리오

### 1. 기본 DHCPv6 서버 테스트

```bash
# 서버 시작
sudo python3 dhcpv6_server_simulator.py --interface eth0

# 클라이언트 1개로 기본 동작 확인
sudo python3 dhcpv6_simulator.py --interface eth0
```

**예상 결과:**
- 클라이언트: SOLICIT → ADVERTISE → REQUEST → REPLY → BOUND
- 서버: 주소 `2001:db8:1::1` 할당

### 2. Prefix Delegation 테스트

```bash
# 서버: /56 prefix 위임
sudo python3 dhcpv6_server_simulator.py \
  --interface eth0 \
  --prefix-pool 2001:db8:1000::/48 \
  --prefix-length 56

# 클라이언트: PD 요청
sudo python3 dhcpv6_simulator.py \
  --interface eth0 \
  --prefix-delegation
```

**예상 결과:**
- 클라이언트: `2001:db8:1000::/56` prefix 할당
- 서버: 다음 클라이언트에게 `2001:db8:1000:100::/56` 할당

### 3. 부하 테스트 (100 클라이언트)

```bash
# 서버
sudo python3 dhcpv6_server_simulator.py \
  --interface eth0 \
  --address-pool 2001:db8::/56 \
  --stats-interval 10

# 클라이언트
sudo python3 dhcpv6_simulator.py \
  --interface eth0 \
  --clients 100 \
  --duration 300 \
  --no-dashboard
```

**통계 예시:**
```
SOLICIT received:    100
ADVERTISE sent:      100
REQUEST received:    100
REPLY sent:          100
Success rate:        100%
```

### 4. Renew/Rebind 테스트

```bash
# 서버: 짧은 lifetime (테스트용)
sudo python3 dhcpv6_server_simulator.py \
  --interface eth0 \
  --valid-lifetime 60 \
  --preferred-lifetime 30

# 클라이언트: Renew 활성화
sudo python3 dhcpv6_simulator.py \
  --interface eth0 \
  --renew \
  --duration 120
```

**예상 동작:**
- T1 (30초): RENEW 전송
- T2 (48초): REBIND 전송 (RENEW 실패 시)

### 5. Relay Agent 시뮬레이션

```bash
# 서버 (유니캐스트 주소 필요)
sudo python3 dhcpv6_server_simulator.py --interface eth0

# 클라이언트 (Relay 모드)
sudo python3 dhcpv6_simulator.py \
  --interface eth0 \
  --relay-server fe80::1 \
  --clients 10
```

### 6. 재전송 동작 확인 (서버 없이)

```bash
# 서버 없이 클라이언트만 실행 (verbose 모드)
sudo python3 dhcpv6_simulator.py \
  --interface eth0 \
  --verbose \
  --no-dashboard

# 로그 예시:
# INFO - Sending SOLICIT message (multicast)
# INFO - Retransmitting SOLICIT (attempt 1, next in 2.1s)
# INFO - Retransmitting SOLICIT (attempt 2, next in 4.3s)
# INFO - Retransmitting SOLICIT (attempt 3, next in 8.7s)
```

---

## 트러블슈팅

### 문제: `libpcap is not available` 에러

**증상:**
```
ImportError: libpcap is not available. Cannot compile filter !
```

**해결:**
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel

# macOS
brew install libpcap

# 또는 코드가 이미 Python 레벨 필터링으로 우회하도록 수정됨
```

### 문제: `Permission denied` (root 권한 필요)

**증상:**
```
PermissionError: [Errno 1] Operation not permitted
```

**해결:**
```bash
# sudo 사용
sudo python3 dhcpv6_simulator.py --interface eth0

# 또는 root로 실행
su -
python3 dhcpv6_simulator.py --interface eth0
```

### 문제: 패킷이 전송되지 않음

**증상:**
- 클라이언트가 SOLICIT 상태에서 멈춤
- 서버가 패킷을 받지 못함

**확인사항:**
```bash
# 1. 인터페이스 확인
ip addr show eth0

# 2. IPv6 활성화 확인
sysctl net.ipv6.conf.eth0.disable_ipv6

# 3. 패킷 캡처로 확인
sudo tcpdump -i eth0 -n 'udp port 546 or udp port 547'

# 4. 인터페이스 link-local 주소 확인
ip -6 addr show eth0 | grep fe80
```

### 문제: 대시보드가 깨짐

**증상:**
- 터미널에서 대시보드가 제대로 표시되지 않음

**해결:**
```bash
# 1. 터미널 크기 확인 (최소 80x24 권장)
echo $COLUMNS $LINES

# 2. 대시보드 비활성화
sudo python3 dhcpv6_simulator.py --interface eth0 --no-dashboard

# 3. tmux/screen 사용 시 TERM 환경변수 확인
echo $TERM
export TERM=xterm-256color
```

### 문제: 서버가 응답하지 않음

**확인사항:**
```bash
# 1. 서버 로그 확인
sudo python3 dhcpv6_server_simulator.py --interface eth0 --verbose

# 2. 방화벽 확인
sudo ip6tables -L -n

# 3. 서버와 클라이언트가 같은 네트워크인지 확인
ping6 ff02::1%eth0
```

---

## RFC 8415 준수

이 도구는 [RFC 8415 - Dynamic Host Configuration Protocol for IPv6 (DHCPv6)](https://tools.ietf.org/html/rfc8415)를 따릅니다:

### 구현된 RFC 기능

| 섹션 | 기능 | 구현 | 비고 |
|------|------|------|------|
| 6.6 | Client Identifier (DUID) | ✅ | DUID-LLT 사용 |
| 6.7 | Server Identifier | ✅ | |
| 15 | Reliability of Client Initiated Message Exchanges | ✅ | Exponential backoff |
| 18.2.1 | SOLICIT Message | ✅ | |
| 18.2.2 | ADVERTISE Message | ✅ | |
| 18.2.3 | REQUEST Message | ✅ | |
| 18.2.8 | REPLY Message | ✅ | |
| 18.2.4 | RENEW Message | ✅ | T1 timer |
| 18.2.6 | REBIND Message | ✅ | T2 timer |
| 21.9 | IA_NA (Address) | ✅ | |
| 21.21 | IA_PD (Prefix) | ✅ | |
| 20 | Relay Agent | ✅ | RELAY-FORW/REPL |

### 재전송 파라미터 (RFC 8415 Section 15)

| 메시지 | IRT | MRT | MRC | MRD |
|--------|-----|-----|-----|-----|
| SOLICIT | 1s | 3600s | 0 (무제한) | - |
| REQUEST | 1s | 30s | 10 | - |
| RENEW | 10s | 600s | 0 | - |
| REBIND | 10s | 600s | 0 | - |

---

## 라이선스

MIT License

Copyright (c) 2025

---

## 기여

버그 리포트 및 기능 제안은 GitHub Issues를 통해 제출해주세요.

---

## 참고 자료

- [RFC 8415 - DHCPv6](https://tools.ietf.org/html/rfc8415)
- [RFC 3315 - DHCP for IPv6 (Obsoleted)](https://tools.ietf.org/html/rfc3315)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [IANA DHCPv6 Parameters](https://www.iana.org/assignments/dhcpv6-parameters/)

---

**Made with ❤️ for network testing**
