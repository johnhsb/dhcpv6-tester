"""DHCPv6 클라이언트 구현"""

import time
import threading
import logging
from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6_Reply
from dhcpv6_packet import DHCPv6Packet, DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class DHCPv6Client:
    """DHCPv6 클라이언트"""

    # 클라이언트 상태
    STATE_INIT = "INIT"
    STATE_SELECTING = "SELECTING"
    STATE_REQUESTING = "REQUESTING"
    STATE_BOUND = "BOUND"
    STATE_RENEWING = "RENEWING"
    STATE_REBINDING = "REBINDING"

    def __init__(self, interface, client_id=None, request_prefix=False):
        """
        DHCPv6 클라이언트 초기화

        Args:
            interface: 네트워크 인터페이스 이름
            client_id: 클라이언트 ID (None이면 자동 생성)
            request_prefix: Prefix Delegation 요청 여부
        """
        self.interface = interface
        self.request_prefix = request_prefix
        self.client_id = client_id or f"client-{uuid.uuid4().hex[:8]}"
        self.logger = logging.getLogger(f"DHCPv6Client[{self.client_id}]")

        # 패킷 빌더
        self.packet_builder = DHCPv6Packet()

        # 상태 관리
        self.state = self.STATE_INIT
        self.server_duid = None
        self.assigned_addresses = []
        self.assigned_prefixes = []

        # 타이머 관리
        self.renew_timer = None
        self.rebind_timer = None
        self.renew_interval = None
        self.rebind_interval = None

        # 패킷 수신 스레드
        self.running = False
        self.recv_thread = None

    def start(self):
        """클라이언트 시작 및 주소 획득 프로세스 시작"""
        self.logger.info(f"Starting DHCPv6 client on interface {self.interface}")
        self.running = True

        # 패킷 수신 스레드 시작
        self.recv_thread = threading.Thread(target=self._recv_packets, daemon=True)
        self.recv_thread.start()

        # DHCP 프로세스 시작
        self._send_solicit()

    def stop(self):
        """클라이언트 중지"""
        self.logger.info("Stopping DHCPv6 client")
        self.running = False

        # 타이머 취소
        if self.renew_timer:
            self.renew_timer.cancel()
        if self.rebind_timer:
            self.rebind_timer.cancel()

        if self.recv_thread:
            self.recv_thread.join(timeout=2)

    def _send_solicit(self):
        """SOLICIT 메시지 전송"""
        self.logger.info("Sending SOLICIT message")
        self.state = self.STATE_SELECTING

        pkt = self.packet_builder.build_solicit(
            request_ia_na=True,
            request_ia_pd=self.request_prefix
        )

        try:
            # Link-local 주소 가져오기
            self._set_src_addr(pkt)
            send(pkt, iface=self.interface, verbose=False)
            self.logger.debug("SOLICIT sent successfully")
        except Exception as e:
            self.logger.error(f"Failed to send SOLICIT: {e}")

    def _send_request(self):
        """REQUEST 메시지 전송"""
        self.logger.info("Sending REQUEST message")
        self.state = self.STATE_REQUESTING

        # ADVERTISE에서 받은 주소/prefix 사용
        ia_na_addr = self.assigned_addresses[0]['address'] if self.assigned_addresses else None
        ia_pd_prefix = None
        if self.assigned_prefixes:
            prefix_info = self.assigned_prefixes[0]
            ia_pd_prefix = (prefix_info['prefix'], prefix_info['prefix_length'])

        pkt = self.packet_builder.build_request(
            server_duid=self.server_duid,
            ia_na_addr=ia_na_addr,
            ia_pd_prefix=ia_pd_prefix
        )

        try:
            self._set_src_addr(pkt)
            send(pkt, iface=self.interface, verbose=False)
            self.logger.debug("REQUEST sent successfully")
        except Exception as e:
            self.logger.error(f"Failed to send REQUEST: {e}")

    def _send_renew(self):
        """RENEW 메시지 전송"""
        self.logger.info("Sending RENEW message")
        self.state = self.STATE_RENEWING

        ia_na_addr = self.assigned_addresses[0]['address'] if self.assigned_addresses else None
        ia_pd_prefix = None
        if self.assigned_prefixes:
            prefix_info = self.assigned_prefixes[0]
            ia_pd_prefix = (prefix_info['prefix'], prefix_info['prefix_length'])

        pkt = self.packet_builder.build_renew(
            server_duid=self.server_duid,
            ia_na_addr=ia_na_addr,
            ia_pd_prefix=ia_pd_prefix
        )

        try:
            self._set_src_addr(pkt)
            send(pkt, iface=self.interface, verbose=False)
            self.logger.debug("RENEW sent successfully")
        except Exception as e:
            self.logger.error(f"Failed to send RENEW: {e}")

    def _send_rebind(self):
        """REBIND 메시지 전송"""
        self.logger.info("Sending REBIND message")
        self.state = self.STATE_REBINDING

        ia_na_addr = self.assigned_addresses[0]['address'] if self.assigned_addresses else None
        ia_pd_prefix = None
        if self.assigned_prefixes:
            prefix_info = self.assigned_prefixes[0]
            ia_pd_prefix = (prefix_info['prefix'], prefix_info['prefix_length'])

        pkt = self.packet_builder.build_rebind(
            ia_na_addr=ia_na_addr,
            ia_pd_prefix=ia_pd_prefix
        )

        try:
            self._set_src_addr(pkt)
            send(pkt, iface=self.interface, verbose=False)
            self.logger.debug("REBIND sent successfully")
        except Exception as e:
            self.logger.error(f"Failed to send REBIND: {e}")

    def _recv_packets(self):
        """DHCPv6 패킷 수신 스레드"""
        filter_str = f"udp and dst port {DHCPV6_CLIENT_PORT}"

        def packet_handler(pkt):
            if not self.running:
                return

            try:
                self._handle_packet(pkt)
            except Exception as e:
                self.logger.error(f"Error handling packet: {e}")

        self.logger.debug(f"Starting packet capture with filter: {filter_str}")
        sniff(
            iface=self.interface,
            filter=filter_str,
            prn=packet_handler,
            store=False,
            stop_filter=lambda x: not self.running
        )

    def _handle_packet(self, pkt):
        """수신한 DHCPv6 패킷 처리"""
        if pkt.haslayer(DHCP6_Advertise) and self.state == self.STATE_SELECTING:
            self._handle_advertise(pkt)
        elif pkt.haslayer(DHCP6_Reply):
            if self.state == self.STATE_REQUESTING:
                self._handle_reply(pkt)
            elif self.state == self.STATE_RENEWING:
                self._handle_renew_reply(pkt)
            elif self.state == self.STATE_REBINDING:
                self._handle_rebind_reply(pkt)

    def _handle_advertise(self, pkt):
        """ADVERTISE 메시지 처리"""
        self.logger.info("Received ADVERTISE message")

        parsed = DHCPv6Packet.parse_reply(pkt)

        if parsed['server_duid']:
            self.server_duid = parsed['server_duid']
            self.assigned_addresses = parsed['addresses']
            self.assigned_prefixes = parsed['prefixes']

            self.logger.info(f"Server DUID: {self.server_duid.hex()}")
            for addr_info in self.assigned_addresses:
                self.logger.info(f"Offered Address: {addr_info['address']}")
            for prefix_info in self.assigned_prefixes:
                self.logger.info(
                    f"Offered Prefix: {prefix_info['prefix']}/{prefix_info['prefix_length']}"
                )

            # REQUEST 전송
            self._send_request()

    def _handle_reply(self, pkt):
        """REPLY 메시지 처리 (REQUEST에 대한 응답)"""
        self.logger.info("Received REPLY message")

        parsed = DHCPv6Packet.parse_reply(pkt)

        self.assigned_addresses = parsed['addresses']
        self.assigned_prefixes = parsed['prefixes']

        for addr_info in self.assigned_addresses:
            self.logger.info(
                f"✓ Assigned Address: {addr_info['address']} "
                f"(Valid: {addr_info['valid_lifetime']}s, Preferred: {addr_info['preferred_lifetime']}s)"
            )

        for prefix_info in self.assigned_prefixes:
            self.logger.info(
                f"✓ Assigned Prefix: {prefix_info['prefix']}/{prefix_info['prefix_length']} "
                f"(Valid: {prefix_info['valid_lifetime']}s, Preferred: {prefix_info['preferred_lifetime']}s)"
            )

        # BOUND 상태로 전환
        self.state = self.STATE_BOUND

        # T1, T2 타이머 설정 (주소가 있는 경우)
        if self.assigned_addresses:
            valid_lifetime = self.assigned_addresses[0]['valid_lifetime']
            # T1 = 0.5 * valid_lifetime, T2 = 0.8 * valid_lifetime
            self.renew_interval = valid_lifetime * 0.5
            self.rebind_interval = valid_lifetime * 0.8

            self.logger.info(f"Setting RENEW timer to {self.renew_interval}s")
            self.renew_timer = threading.Timer(self.renew_interval, self._send_renew)
            self.renew_timer.start()

            self.logger.info(f"Setting REBIND timer to {self.rebind_interval}s")
            self.rebind_timer = threading.Timer(self.rebind_interval, self._send_rebind)
            self.rebind_timer.start()

    def _handle_renew_reply(self, pkt):
        """REPLY 메시지 처리 (RENEW에 대한 응답)"""
        self.logger.info("Received REPLY for RENEW")

        parsed = DHCPv6Packet.parse_reply(pkt)

        self.assigned_addresses = parsed['addresses']
        self.assigned_prefixes = parsed['prefixes']

        for addr_info in self.assigned_addresses:
            self.logger.info(f"✓ Renewed Address: {addr_info['address']}")

        for prefix_info in self.assigned_prefixes:
            self.logger.info(f"✓ Renewed Prefix: {prefix_info['prefix']}/{prefix_info['prefix_length']}")

        # BOUND 상태로 복귀
        self.state = self.STATE_BOUND

        # 타이머 재설정
        if self.assigned_addresses:
            valid_lifetime = self.assigned_addresses[0]['valid_lifetime']
            self.renew_interval = valid_lifetime * 0.5
            self.rebind_interval = valid_lifetime * 0.8

            self.renew_timer = threading.Timer(self.renew_interval, self._send_renew)
            self.renew_timer.start()

            self.rebind_timer = threading.Timer(self.rebind_interval, self._send_rebind)
            self.rebind_timer.start()

    def _handle_rebind_reply(self, pkt):
        """REPLY 메시지 처리 (REBIND에 대한 응답)"""
        self.logger.info("Received REPLY for REBIND")

        parsed = DHCPv6Packet.parse_reply(pkt)

        # 새로운 서버일 수 있음
        if parsed['server_duid']:
            self.server_duid = parsed['server_duid']

        self.assigned_addresses = parsed['addresses']
        self.assigned_prefixes = parsed['prefixes']

        for addr_info in self.assigned_addresses:
            self.logger.info(f"✓ Rebound Address: {addr_info['address']}")

        for prefix_info in self.assigned_prefixes:
            self.logger.info(f"✓ Rebound Prefix: {prefix_info['prefix']}/{prefix_info['prefix_length']}")

        # BOUND 상태로 복귀
        self.state = self.STATE_BOUND

        # 타이머 재설정
        if self.assigned_addresses:
            valid_lifetime = self.assigned_addresses[0]['valid_lifetime']
            self.renew_interval = valid_lifetime * 0.5
            self.rebind_interval = valid_lifetime * 0.8

            self.renew_timer = threading.Timer(self.renew_interval, self._send_renew)
            self.renew_timer.start()

            self.rebind_timer = threading.Timer(self.rebind_interval, self._send_rebind)
            self.rebind_timer.start()

    def _set_src_addr(self, pkt):
        """패킷의 소스 주소를 인터페이스의 link-local 주소로 설정"""
        try:
            # 인터페이스의 IPv6 link-local 주소 가져오기
            import netifaces
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET6 in addrs:
                for addr_info in addrs[netifaces.AF_INET6]:
                    addr = addr_info['addr'].split('%')[0]  # zone id 제거
                    if addr.startswith('fe80:'):
                        pkt[IPv6].src = addr
                        return
            self.logger.warning("No link-local address found, using default")
        except Exception as e:
            self.logger.warning(f"Could not set source address: {e}")

    def get_status(self):
        """클라이언트 상태 정보 반환"""
        return {
            'client_id': self.client_id,
            'state': self.state,
            'addresses': self.assigned_addresses,
            'prefixes': self.assigned_prefixes,
            'server_duid': self.server_duid.hex() if self.server_duid else None
        }
