# DHCPv6 Client Simulator

IPv6용 DHCP 클라이언트 시뮬레이터 with 실시간 대시보드

## 기능

- ✅ 기본 주소 할당 (Solicit-Advertise-Request-Reply)
- ✅ Prefix Delegation (DHCPv6-PD)
- ✅ 다중 클라이언트 동시 시뮬레이션
- ✅ Renew/Rebind 기능
- ✅ **실시간 대시보드** - 클라이언트 상태를 실시간으로 모니터링

## 설치

```bash
pip install -r requirements.txt
```

## 사용법

### 기본 사용 (실시간 대시보드 모드)

```bash
# 단일 클라이언트 실행 (실시간 대시보드)
sudo python3 dhcpv6_simulator.py --interface eth0

# 다중 클라이언트 실행 (10개 클라이언트)
sudo python3 dhcpv6_simulator.py --interface eth0 --clients 10

# Prefix Delegation 요청
sudo python3 dhcpv6_simulator.py --interface eth0 --prefix-delegation

# 모든 기능 활성화
sudo python3 dhcpv6_simulator.py --interface eth0 --clients 5 --prefix-delegation --renew --duration 180
```

### 로그 모드 (대시보드 없이)

```bash
# 실시간 대시보드 비활성화
sudo python3 dhcpv6_simulator.py --interface eth0 --clients 10 --no-dashboard
```

## 실시간 대시보드

기본적으로 프로그램은 실시간 대시보드 모드로 실행됩니다:

- **헤더**: 인터페이스, 실행 시간, 남은 시간 표시
- **클라이언트 테이블**: 각 클라이언트의 상태, 할당된 주소, Prefix 표시
- **통계 패널**: 전체 통계, 상태별 클라이언트 수, 성공률
- **최근 이벤트**: 최근 클라이언트 활동 로그

### 상태 아이콘

- ⚪ INIT - 초기화
- 🔍 SELECTING - ADVERTISE 대기
- 📨 REQUESTING - REPLY 대기
- ✅ BOUND - 주소 할당 완료
- 🔄 RENEWING - 주소 갱신 중
- ⚠️ REBINDING - 재바인딩 중

## 요구사항

- Python 3.7+
- Linux/Unix 시스템 (raw socket 사용)
- root 권한 (패킷 전송을 위해)

## 명령행 옵션

```
--interface, -i     네트워크 인터페이스 이름 (필수)
--clients, -c       시뮬레이션할 클라이언트 수 (기본값: 1)
--prefix-delegation, -p    Prefix Delegation 요청 활성화
--duration, -d      실행 시간(초) (기본값: 60)
--renew             Renew/Rebind 테스트 활성화
--no-dashboard      실시간 대시보드 비활성화
--verbose, -v       상세 로그 출력
```
