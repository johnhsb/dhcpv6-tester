#!/usr/bin/env python3
"""DHCPv6 클라이언트 시뮬레이터 메인 실행 파일"""

import sys
import time
import signal
import argparse
import logging
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from dhcpv6_client import DHCPv6Client
from dashboard import DHCPv6Dashboard, DashboardRunner

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DHCPv6Simulator")


class DHCPv6Simulator:
    """다중 DHCPv6 클라이언트 시뮬레이터"""

    def __init__(self, interface, num_clients=1, request_prefix=False, relay_server=None, relay_address=None,
                 t1_ratio=0.5, t2_ratio=0.8):
        """
        시뮬레이터 초기화

        Args:
            interface: 네트워크 인터페이스 이름
            num_clients: 시뮬레이션할 클라이언트 수
            request_prefix: Prefix Delegation 요청 여부
            relay_server: Relay 모드 사용 시 DHCPv6 서버 주소
            relay_address: Relay Agent 주소
            t1_ratio: T1 (RENEW) 타이머 비율 (기본값: 0.5)
            t2_ratio: T2 (REBIND) 타이머 비율 (기본값: 0.8)
        """
        self.interface = interface
        self.num_clients = num_clients
        self.request_prefix = request_prefix
        self.relay_server = relay_server
        self.relay_address = relay_address
        self.t1_ratio = t1_ratio
        self.t2_ratio = t2_ratio
        self.clients = []
        self.running = False

    async def start(self):
        """시뮬레이터 시작"""
        logger.info(f"Starting DHCPv6 Simulator with {self.num_clients} client(s)")
        logger.info(f"Interface: {self.interface}")
        logger.info(f"Prefix Delegation: {'Enabled' if self.request_prefix else 'Disabled'}")
        if self.relay_server:
            logger.info(f"Relay Mode: Enabled (Server: {self.relay_server})")
        else:
            logger.info(f"Relay Mode: Disabled (Multicast)")

        self.running = True

        # 다중 클라이언트 생성 및 시작
        loop = asyncio.get_event_loop()
        executor = ThreadPoolExecutor(max_workers=self.num_clients)

        # 클라이언트를 순차적으로 시작 (간격을 두고)
        for i in range(self.num_clients):
            client = DHCPv6Client(
                interface=self.interface,
                client_id=f"client-{i+1}",
                request_prefix=self.request_prefix,
                relay_server=self.relay_server,
                relay_address=self.relay_address,
                t1_ratio=self.t1_ratio,
                t2_ratio=self.t2_ratio
            )
            self.clients.append(client)

            # 스레드에서 클라이언트 시작
            await loop.run_in_executor(executor, client.start)

            # 다음 클라이언트 시작 전 짧은 지연
            if i < self.num_clients - 1:
                await asyncio.sleep(0.5)

        logger.info(f"All {self.num_clients} clients started")

    async def stop(self):
        """시뮬레이터 중지"""
        logger.info("Stopping DHCPv6 Simulator")
        self.running = False

        # 모든 클라이언트 중지
        loop = asyncio.get_event_loop()
        executor = ThreadPoolExecutor(max_workers=len(self.clients))

        for client in self.clients:
            await loop.run_in_executor(executor, client.stop)

        logger.info("All clients stopped")

    async def monitor(self, interval=5):
        """클라이언트 상태 모니터링 (5초 단위 통계 출력)"""
        while self.running:
            await asyncio.sleep(interval)

            if not self.running:
                break

            # 통합 통계 수집
            total_clients = len(self.clients)
            total_solicit = 0
            total_advertise = 0
            total_request = 0
            total_reply = 0
            total_renew = 0
            total_rebind = 0
            total_retrans = 0
            bound_clients = 0
            total_addresses = 0
            total_prefixes = 0

            # 평균 SARR 시간 계산을 위한 변수
            sarr_times = []

            for client in self.clients:
                status = client.get_status()
                stats = status.get('stats', {})

                total_solicit += stats.get('solicit_sent', 0)
                total_advertise += stats.get('advertise_received', 0)
                total_request += stats.get('request_sent', 0)
                total_reply += stats.get('reply_received', 0)
                total_renew += stats.get('renew_sent', 0)
                total_rebind += stats.get('rebind_sent', 0)
                total_retrans += stats.get('total_retransmissions', 0)

                if status['state'] == DHCPv6Client.STATE_BOUND:
                    bound_clients += 1

                    # SARR 완료 시간 계산
                    start_time = stats.get('start_time')
                    bound_time = stats.get('bound_time')
                    if start_time and bound_time:
                        sarr_times.append(bound_time - start_time)

                total_addresses += len(status['addresses'])
                total_prefixes += len(status['prefixes'])

            # 성공률 계산
            success_rate = (bound_clients / total_clients * 100) if total_clients > 0 else 0

            # SARR 평균 시간 계산
            avg_sarr_time = sum(sarr_times) / len(sarr_times) if sarr_times else 0

            # 통계 출력
            logger.info("=" * 80)
            logger.info(f"[Statistics] Total Clients: {total_clients}")
            logger.info(f"  SOLICIT Sent: {total_solicit} | ADVERTISE Rcvd: {total_advertise}")
            logger.info(f"  REQUEST Sent: {total_request} | REPLY Rcvd: {total_reply}")
            logger.info(f"  RENEW Sent: {total_renew} | REBIND Sent: {total_rebind}")
            logger.info(f"  Total Retransmissions: {total_retrans}")
            logger.info(f"  BOUND Clients: {bound_clients}/{total_clients} ({success_rate:.1f}%)")
            logger.info(f"  Addresses Assigned: {total_addresses} | Prefixes Assigned: {total_prefixes}")
            if avg_sarr_time > 0:
                logger.info(f"  Avg SARR Time: {avg_sarr_time:.2f}s")
            logger.info("=" * 80)

    def print_summary(self):
        """최종 요약 정보 출력"""
        logger.info("\n" + "=" * 80)
        logger.info("Final Summary")
        logger.info("=" * 80)

        # 통합 통계 수집
        total_clients = len(self.clients)
        total_solicit = 0
        total_advertise = 0
        total_request = 0
        total_reply = 0
        total_renew = 0
        total_rebind = 0
        total_retrans = 0
        bound_clients = 0
        total_addresses = 0
        total_prefixes = 0
        sarr_times = []

        for client in self.clients:
            status = client.get_status()
            stats = status.get('stats', {})

            total_solicit += stats.get('solicit_sent', 0)
            total_advertise += stats.get('advertise_received', 0)
            total_request += stats.get('request_sent', 0)
            total_reply += stats.get('reply_received', 0)
            total_renew += stats.get('renew_sent', 0)
            total_rebind += stats.get('rebind_sent', 0)
            total_retrans += stats.get('total_retransmissions', 0)

            if status['state'] == DHCPv6Client.STATE_BOUND:
                bound_clients += 1
                start_time = stats.get('start_time')
                bound_time = stats.get('bound_time')
                if start_time and bound_time:
                    sarr_times.append(bound_time - start_time)

            total_addresses += len(status['addresses'])
            total_prefixes += len(status['prefixes'])

        # 성공률 계산
        success_rate = (bound_clients / total_clients * 100) if total_clients > 0 else 0
        avg_sarr_time = sum(sarr_times) / len(sarr_times) if sarr_times else 0

        # 통계 출력
        logger.info(f"\nTotal Clients: {total_clients}")
        logger.info(f"BOUND Clients: {bound_clients} ({success_rate:.1f}%)")
        logger.info(f"\nSARR Statistics:")
        logger.info(f"  SOLICIT Sent: {total_solicit}")
        logger.info(f"  ADVERTISE Received: {total_advertise}")
        logger.info(f"  REQUEST Sent: {total_request}")
        logger.info(f"  REPLY Received: {total_reply}")
        logger.info(f"  Success Rate: {success_rate:.1f}%")
        if avg_sarr_time > 0:
            logger.info(f"  Average SARR Time: {avg_sarr_time:.2f}s")

        logger.info(f"\nRenewal Statistics:")
        logger.info(f"  RENEW Sent: {total_renew}")
        logger.info(f"  REBIND Sent: {total_rebind}")

        logger.info(f"\nRetransmission Statistics:")
        logger.info(f"  Total Retransmissions: {total_retrans}")

        logger.info(f"\nAssignment Statistics:")
        logger.info(f"  Total Addresses Assigned: {total_addresses}")
        logger.info(f"  Total Prefixes Assigned: {total_prefixes}")

        logger.info("\nClient Details:")
        for client in self.clients:
            status = client.get_status()
            logger.info(f"\n[{status['client_id']}]")
            logger.info(f"  State: {status['state']}")

            if status['addresses']:
                for addr in status['addresses']:
                    logger.info(f"  Address: {addr['address']}")

            if status['prefixes']:
                for prefix in status['prefixes']:
                    logger.info(f"  Prefix: {prefix['prefix']}/{prefix['prefix_length']}")

        logger.info("=" * 80)


async def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description='DHCPv6 클라이언트 시뮬레이터',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
사용 예시:
  # 단일 클라이언트 (기본 주소 할당)
  sudo python3 dhcpv6_simulator.py --interface eth0

  # 10개 클라이언트 동시 실행
  sudo python3 dhcpv6_simulator.py --interface eth0 --clients 10

  # Prefix Delegation 요청
  sudo python3 dhcpv6_simulator.py --interface eth0 --prefix-delegation

  # 모든 기능 활성화
  sudo python3 dhcpv6_simulator.py --interface eth0 --clients 5 --prefix-delegation --renew --duration 120
        '''
    )

    parser.add_argument(
        '--interface', '-i',
        required=True,
        help='네트워크 인터페이스 이름 (예: eth0, en0)'
    )

    parser.add_argument(
        '--clients', '-c',
        type=int,
        default=1,
        help='시뮬레이션할 클라이언트 수 (기본값: 1)'
    )

    parser.add_argument(
        '--prefix-delegation', '-p',
        action='store_true',
        help='Prefix Delegation 요청 활성화'
    )

    parser.add_argument(
        '--duration', '-d',
        type=int,
        default=60,
        help='시뮬레이션 실행 시간 (초, 기본값: 60)'
    )

    parser.add_argument(
        '--monitor-interval',
        type=int,
        default=5,
        help='상태 모니터링 간격 (초, 기본값: 5)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='상세 로그 출력'
    )

    parser.add_argument(
        '--renew',
        action='store_true',
        help='Renew/Rebind 기능 테스트 (T1/T2 타이머 활성화)'
    )

    parser.add_argument(
        '--t1-ratio',
        type=float,
        default=0.5,
        help='T1 (RENEW) 타이머 비율 (기본값: 0.5 = valid_lifetime의 50%%)'
    )

    parser.add_argument(
        '--t2-ratio',
        type=float,
        default=0.8,
        help='T2 (REBIND) 타이머 비율 (기본값: 0.8 = valid_lifetime의 80%%)'
    )

    parser.add_argument(
        '--no-dashboard',
        action='store_true',
        help='실시간 대시보드 비활성화 (로그 모드 사용)'
    )

    parser.add_argument(
        '--relay-server',
        type=str,
        help='Relay 모드: DHCPv6 서버 IPv6 주소 (예: fe80::1, 2001:db8::1)'
    )

    parser.add_argument(
        '--relay-address',
        type=str,
        help='Relay 모드: Relay Agent IPv6 주소 (기본값: ::)'
    )

    args = parser.parse_args()

    # 로그 레벨 설정
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif not args.no_dashboard:
        # 대시보드 모드에서는 WARNING 이상만 출력 (화면이 깨지지 않도록)
        logging.getLogger().setLevel(logging.WARNING)

    # root 권한 확인
    if os.geteuid() != 0:
        logger.error("이 프로그램은 root 권한이 필요합니다. sudo를 사용하세요.")
        sys.exit(1)

    # 시뮬레이터 생성
    simulator = DHCPv6Simulator(
        interface=args.interface,
        num_clients=args.clients,
        request_prefix=args.prefix_delegation,
        relay_server=args.relay_server,
        relay_address=args.relay_address,
        t1_ratio=args.t1_ratio,
        t2_ratio=args.t2_ratio
    )

    # 종료 이벤트 생성
    stop_event = asyncio.Event()

    # 시그널 핸들러 설정
    def signal_handler(sig, frame):
        logger.info("\nReceived interrupt signal, stopping...")
        stop_event.set()  # 이벤트를 set하여 즉시 깨우기

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # 시뮬레이터 시작
        await simulator.start()

        if args.no_dashboard:
            # 기존 로그 방식 모니터링
            monitor_task = asyncio.create_task(
                simulator.monitor(interval=args.monitor_interval)
            )

            # 지정된 시간 동안 실행하거나 종료 신호 대기
            logger.info(f"Running for {args.duration} seconds...")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=args.duration)
                logger.info("Stop signal received")
            except asyncio.TimeoutError:
                logger.info("Duration completed")

            # 정리
            await simulator.stop()
            monitor_task.cancel()

        else:
            # 실시간 대시보드 사용
            dashboard = DHCPv6Dashboard(
                clients=simulator.clients,
                interface=args.interface,
                duration=args.duration,
                request_prefix=args.prefix_delegation,
                relay_server=args.relay_server,
                relay_address=args.relay_address
            )

            dashboard_runner = DashboardRunner(dashboard, update_interval=0.5)

            # 대시보드를 별도 스레드에서 실행
            dashboard_thread = threading.Thread(target=dashboard_runner.start, daemon=True)
            dashboard_thread.start()

            # 지정된 시간 동안 실행하거나 종료 신호 대기
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=args.duration)
                logger.info("Stop signal received")
            except asyncio.TimeoutError:
                pass  # Duration completed

            # 정리
            dashboard_runner.stop()
            await simulator.stop()
            dashboard_thread.join(timeout=2)

        # 요약 정보 출력
        print("\n")  # 대시보드 후 줄바꿈
        simulator.print_summary()

    except KeyboardInterrupt:
        logger.info("\nReceived interrupt signal, stopping...")
        await simulator.stop()
        print("\n")
        simulator.print_summary()
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        await simulator.stop()
        sys.exit(1)


if __name__ == '__main__':
    import os
    asyncio.run(main())
