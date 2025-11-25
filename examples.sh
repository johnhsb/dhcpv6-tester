#!/bin/bash
# DHCPv6 Simulator 사용 예제

echo "DHCPv6 Client Simulator 예제"
echo "=============================="
echo ""

# 인터페이스 확인
echo "1. 네트워크 인터페이스 확인:"
echo "   ip -6 addr show"
echo ""

# 예제 1: 단일 클라이언트 (실시간 대시보드)
echo "2. 단일 클라이언트 실행 (60초, 실시간 대시보드):"
echo "   sudo python3 dhcpv6_simulator.py --interface eth0 --duration 60"
echo ""

# 예제 2: 다중 클라이언트 (실시간 대시보드)
echo "3. 10개 클라이언트 동시 실행 (실시간 대시보드):"
echo "   sudo python3 dhcpv6_simulator.py --interface eth0 --clients 10 --duration 120"
echo ""

# 예제 3: Prefix Delegation (실시간 대시보드)
echo "4. Prefix Delegation 요청 (실시간 대시보드):"
echo "   sudo python3 dhcpv6_simulator.py --interface eth0 --prefix-delegation --duration 60"
echo ""

# 예제 4: 모든 기능
echo "5. 모든 기능 활성화 (5개 클라이언트, PD, Renew/Rebind, 실시간 대시보드):"
echo "   sudo python3 dhcpv6_simulator.py --interface eth0 --clients 5 --prefix-delegation --renew --duration 180"
echo ""

# 예제 5: 로그 모드 (대시보드 없이)
echo "6. 로그 모드로 실행 (대시보드 비활성화):"
echo "   sudo python3 dhcpv6_simulator.py --interface eth0 --clients 10 --no-dashboard --duration 120"
echo ""

# 예제 6: 상세 로그
echo "7. 상세 로그 출력 (디버깅용):"
echo "   sudo python3 dhcpv6_simulator.py --interface eth0 --verbose --no-dashboard --duration 60"
echo ""

# 예제 7: 부하 테스트
echo "8. 부하 테스트 (100개 클라이언트, 실시간 대시보드):"
echo "   sudo python3 dhcpv6_simulator.py --interface eth0 --clients 100 --duration 300"
echo ""

echo "실시간 대시보드 기능:"
echo "- 기본적으로 실시간 대시보드가 활성화됩니다"
echo "- 각 클라이언트의 상태를 실시간으로 모니터링"
echo "- 통계 및 성공률 표시"
echo "- --no-dashboard 옵션으로 비활성화 가능"
echo ""

echo "주의사항:"
echo "- root 권한(sudo)이 필요합니다"
echo "- 실제 DHCPv6 서버가 네트워크에 있어야 합니다"
echo "- eth0를 실제 네트워크 인터페이스 이름으로 변경하세요"
echo ""
