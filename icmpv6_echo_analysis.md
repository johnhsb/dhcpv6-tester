# ICMPv6 Echo Request Tool 분석 문서

## 📋 프로그램 개요

**목적**: ICMPv6 Echo Request 패킷을 전송하여 IPv6 네트워크 연결성을 테스트하는 도구 (IPv6 버전의 ping)

**언어**: C
**요구사항**: root/sudo 권한 (raw socket 사용)
**컴파일**: `gcc -o icmpv6_echo icmpv6_echo.c`

---

## 🎯 주요 기능

### 1. **커스텀 소스 IP 지정 (핵심 차별화 기능)**
- 일반 ping과 달리 송신 IPv6 주소를 명시적으로 지정 가능
- `bind()` 시스템 콜로 소켓을 특정 소스 주소에 바인딩 (icmpv6_echo.c:97)
- Link-local 주소 테스트 시 인터페이스 지정 지원 (`fe80::1%eth0` 형식)

### 2. **가변 패킷 크기**
- 8~65535 바이트 범위의 ICMP 패킷 생성 가능
- MTU 테스트, 네트워크 단편화(fragmentation) 테스트에 활용
- 페이로드는 'A' 문자로 패딩 (icmpv6_echo.c:147)

### 3. **다양한 ICMP 응답 처리**
- Echo Reply: 정상 응답 (type 129)
- Packet Too Big: PMTU Discovery 관련 (type 2) - icmpv6_echo.c:193
- Destination Unreachable: 도달 불가 (type 1) - icmpv6_echo.c:198
- Time Exceeded: TTL 초과 (type 3) - icmpv6_echo.c:202

### 4. **RTT 측정**
- `gettimeofday()`로 마이크로초 단위 왕복 시간 측정
- 밀리초 단위로 출력 (icmpv6_echo.c:181-182)

### 5. **통계 수집**
- 전송/수신/손실 패킷 수 추적
- 패킷 손실률 백분율 계산 (icmpv6_echo.c:324)

---

## 🏗️ 코드 구조 분석

### 데이터 구조

```c
typedef struct {
    char *dest_addr;      // 목적지 IPv6 주소
    char *src_addr;       // 소스 IPv6 주소 (선택)
    int packet_size;      // 패킷 크기 (8-65535)
    int count;            // 전송 횟수 (기본 4)
    int timeout;          // 응답 타임아웃 (기본 5초)
} test_config_t;
```

### 주요 함수

#### 1. `send_icmpv6_echo()` (icmpv6_echo.c:58-224)
각 ICMP Echo Request 전송 및 응답 대기 처리:

```
Socket 생성 (SOCK_RAW, IPPROTO_ICMPV6)
    ↓
소스 주소 바인딩 (선택 사항)
    ↓
ICMP 패킷 구성 (type=128, id=PID, seq)
    ↓
sendto() → 패킷 전송
    ↓
recvfrom() → 타임아웃 내 응답 대기
    ↓
응답 분석 및 RTT 계산
```

**핵심 구현 세부사항**:

- **Link-local 주소 처리** (icmpv6_echo.c:77-89, 115-126):
  ```c
  // "fe80::1%eth0" → 주소와 인터페이스 분리
  char *percent = strchr(addr_copy, '%');
  if (percent != NULL) {
      unsigned int if_index = if_nametoindex(if_name);
      sockaddr.sin6_scope_id = if_index;
  }
  ```

- **ICMP 헤더 구성** (icmpv6_echo.c:138-142):
  ```c
  icmp->icmp6_type = ICMP6_ECHO_REQUEST;  // type 128
  icmp->icmp6_code = 0;
  icmp->icmp6_id = htons(getpid() & 0xFFFF);  // 프로세스 ID
  icmp->icmp6_seq = htons(seq);               // 시퀀스 번호
  ```

- **Checksum**: 커널이 자동 계산 (IPv6 pseudo-header 포함)

#### 2. `main()` (icmpv6_echo.c:226-331)
- CLI 인자 파싱 (getopt)
- root 권한 확인
- 반복 전송 및 통계 집계

---

## 🔍 특징 및 설계 결정

### ✅ 장점

1. **Source IP 제어**: DHCPv6로 할당받은 주소 테스트에 유용
   - 예: DHCPv6 서버가 할당한 주소가 실제 통신 가능한지 검증

2. **PMTU Discovery 지원**: Packet Too Big 메시지 감지로 경로 MTU 확인 가능

3. **Link-local 주소 지원**: `%interface` 문법으로 scope ID 명시

4. **간결한 구현**: 단일 파일, 외부 라이브러리 의존성 없음

### ⚠️ 제약사항

1. **Socket 재사용 없음**: 매 요청마다 새 소켓 생성/해제 (icmpv6_echo.c:59, 222)
   - 성능 최적화 여지 존재

2. **응답 필터링 미흡**: 모든 ICMPv6 패킷 수신, ID/Sequence 미검증
   - 다른 프로세스의 ICMP 응답과 혼동 가능성

3. **단일 스레드**: 병렬 전송 불가, 패킷 간 200ms 고정 지연 (icmpv6_echo.c:314)

4. **IPv4 미지원**: ICMPv6 전용 (AF_INET6만 사용)

---

## 💡 사용 예시

```bash
# 기본 테스트
sudo ./icmpv6_echo 2001:4860:4860::8888 1500

# DHCPv6 할당 주소로 테스트
sudo ./icmpv6_echo -s 2001:db8:1234::100 2001:4860:4860::8888 1500

# Link-local 통신 (인터페이스 필수)
sudo ./icmpv6_echo -s fe80::1%eth0 fe80::2%eth0 1280

# 대용량 패킷 MTU 테스트
sudo ./icmpv6_echo -c 10 2001:db8::1 9000

# 타임아웃 조정
sudo ./icmpv6_echo -t 10 -c 5 2001:db8::1 2000
```

---

## 🔗 DHCPv6 Simulator와의 연계

이 도구는 현재 프로젝트(DHCPv6 Client Simulator)의 보완 유틸리티로 활용 가능:

1. **주소 할당 검증**: DHCPv6로 받은 IPv6 주소가 실제 통신 가능한지 확인
2. **Prefix Delegation 테스트**: 위임받은 프리픽스 내 주소로 외부 통신 테스트
3. **네트워크 디버깅**: 클라이언트 시뮬레이터가 생성한 MAC/IP 조합의 연결성 확인

**예시 워크플로우**:
```bash
# 1. DHCPv6 시뮬레이터로 주소 할당
sudo python3 dhcpv6_simulator.py -i eth0 -c 1

# 2. 할당받은 주소로 ICMP 테스트 (대시보드에서 주소 확인 후)
sudo ./icmpv6_echo -s 2001:db8:assigned::1 2001:4860:4860::8888 1500
```

---

## 🎓 기술적 인사이트

### Raw Socket 프로그래밍
이 도구는 `SOCK_RAW` 타입 소켓을 사용하여 ICMP 패킷을 직접 제어합니다. 이는 다음을 가능하게 합니다:
- 임의의 소스 IP 설정
- 커스텀 패킷 크기 제어
- ICMP 헤더 직접 조작

### IPv6 주소 처리
Link-local 주소(`fe80::/10`)는 scope ID가 필수적입니다. 코드는 `%` 구분자를 파싱하여 인터페이스 이름을 추출하고 `if_nametoindex()`로 커널의 인터페이스 인덱스를 얻습니다.

### 타이밍 정확도
`gettimeofday()`는 마이크로초 해상도를 제공하지만, 시스템 스케줄링으로 인한 지터(jitter)가 발생할 수 있습니다. 더 정확한 측정을 위해서는 `clock_gettime(CLOCK_MONOTONIC)`을 고려할 수 있습니다.

---

## 결론

이 도구는 IPv6 네트워크 테스트에서 특히 **소스 IP 제어**가 필요한 시나리오(DHCPv6 검증, 멀티호밍 환경)에서 유용합니다. 현재 DHCPv6 시뮬레이터 프로젝트의 테스트 도구로 적합하며, 할당받은 주소의 실제 통신 능력을 검증하는 데 활용할 수 있습니다.

**추천 사용 사례**:
- DHCPv6 주소 할당 검증
- IPv6 네트워크 디버깅
- MTU/PMTU Discovery 테스트
- Link-local 통신 확인
- 네트워크 성능 측정
