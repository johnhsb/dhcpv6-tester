#!/usr/bin/env python3
"""DHCPv6 서버 시뮬레이터 메인 실행 파일"""

import sys
import time
import signal
import argparse
import logging
from dhcpv6_server import DHCPv6Server

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DHCPv6ServerSimulator")


def print_statistics(server):
    """서버 통계 출력"""
    stats = server.get_stats()
    leases = server.get_leases()

    logger.info("=" * 80)
    logger.info("DHCPv6 Server Statistics")
    logger.info("=" * 80)
    logger.info(f"SOLICIT received:    {stats['solicit_received']}")
    logger.info(f"ADVERTISE sent:      {stats['advertise_sent']}")
    logger.info(f"REQUEST received:    {stats['request_received']}")
    logger.info(f"REPLY sent:          {stats['reply_sent']}")
    logger.info(f"RENEW received:      {stats['renew_received']}")
    logger.info(f"REBIND received:     {stats['rebind_received']}")
    logger.info(f"")
    logger.info(f"Total addresses allocated: {stats['total_addresses_allocated']}")
    logger.info(f"Total prefixes allocated:  {stats['total_prefixes_allocated']}")
    logger.info(f"Active leases:             {len(leases)}")
    logger.info("=" * 80)

    if leases:
        logger.info("\nActive Leases:")
        for client_duid, lease_info in leases.items():
            logger.info(f"\nClient DUID: {client_duid}")
            for addr_info in lease_info['addresses']:
                logger.info(f"  Address: {addr_info['address']}")
            for prefix_info in lease_info['prefixes']:
                logger.info(f"  Prefix:  {prefix_info['prefix']}/{prefix_info['prefix_length']}")


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description='DHCPv6 서버 시뮬레이터',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
사용 예시:
  # 기본 설정으로 서버 실행
  sudo python3 dhcpv6_server_simulator.py --interface eth0

  # 주소 풀 및 Prefix 풀 지정
  sudo python3 dhcpv6_server_simulator.py --interface eth0 \\
      --address-pool 2001:db8:1::/64 \\
      --prefix-pool 2001:db8:2::/48 \\
      --prefix-length 56

  # Lifetime 설정
  sudo python3 dhcpv6_server_simulator.py --interface eth0 \\
      --valid-lifetime 3600 \\
      --preferred-lifetime 1800
        '''
    )

    parser.add_argument(
        '--interface', '-i',
        required=True,
        help='네트워크 인터페이스 이름 (예: eth0, en0)'
    )

    parser.add_argument(
        '--address-pool',
        default='2001:db8:1::/64',
        help='IPv6 주소 풀 (CIDR, 기본값: 2001:db8:1::/64)'
    )

    parser.add_argument(
        '--prefix-pool',
        default='2001:db8:2::/48',
        help='Prefix Delegation 풀 (CIDR, 기본값: 2001:db8:2::/48)'
    )

    parser.add_argument(
        '--prefix-length',
        type=int,
        default=56,
        help='위임할 Prefix 길이 (기본값: 56)'
    )

    parser.add_argument(
        '--valid-lifetime',
        type=int,
        default=7200,
        help='Valid lifetime (초, 기본값: 7200)'
    )

    parser.add_argument(
        '--preferred-lifetime',
        type=int,
        default=3600,
        help='Preferred lifetime (초, 기본값: 3600)'
    )

    parser.add_argument(
        '--stats-interval',
        type=int,
        default=30,
        help='통계 출력 간격 (초, 기본값: 30, 0=비활성화)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='상세 로그 출력'
    )

    args = parser.parse_args()

    # 로그 레벨 설정
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # root 권한 확인
    import os
    if os.geteuid() != 0:
        logger.error("이 프로그램은 root 권한이 필요합니다. sudo를 사용하세요.")
        sys.exit(1)

    # 서버 생성
    server = DHCPv6Server(
        interface=args.interface,
        address_pool=args.address_pool,
        prefix_pool=args.prefix_pool,
        prefix_length=args.prefix_length,
        valid_lifetime=args.valid_lifetime,
        preferred_lifetime=args.preferred_lifetime
    )

    # 시그널 핸들러 설정
    def signal_handler(sig, frame):
        logger.info("\nReceived interrupt signal, stopping...")
        server.stop()
        print_statistics(server)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # 서버 시작
        server.start()

        logger.info("\nDHCPv6 server is running. Press Ctrl+C to stop.\n")

        # 통계 출력 루프
        last_stats_time = time.time()

        while True:
            time.sleep(1)

            # 주기적 통계 출력
            if args.stats_interval > 0:
                if time.time() - last_stats_time >= args.stats_interval:
                    print_statistics(server)
                    last_stats_time = time.time()

    except KeyboardInterrupt:
        logger.info("\nReceived interrupt signal, stopping...")
        server.stop()
        print_statistics(server)
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        server.stop()
        sys.exit(1)


if __name__ == '__main__':
    main()
