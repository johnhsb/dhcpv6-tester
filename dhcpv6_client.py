"""DHCPv6 클라이언트 구현"""

import time
import threading
import logging
from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6_Reply, DHCP6_RelayReply
from scapy.layers.l2 import Ether
from dhcpv6_packet import DHCPv6Packet, DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class DHCPv6Client:
    """DHCPv6 클라이언트"""

    # 클라이언트 상태 (DHCPv6 메시지 타입 기반)
    STATE_INIT = "INIT"
    STATE_SOLICIT = "SOLICIT"
    STATE_REQUEST = "REQUEST"
    STATE_BOUND = "BOUND"
    STATE_RENEW = "RENEW"
    STATE_REBIND = "REBIND"

    # RFC 8415 재전송 타이머 파라미터 (초)
    SOL_TIMEOUT = 1      # SOLICIT 초기 재전송 타임아웃
    SOL_MAX_RT = 3600    # SOLICIT 최대 재전송 타임아웃
    REQ_TIMEOUT = 1      # REQUEST 초기 재전송 타임아웃
    REQ_MAX_RT = 30      # REQUEST 최대 재전송 타임아웃
    REQ_MAX_RC = 10      # REQUEST 최대 재시도 횟수

    def __init__(self, interface, client_id=None, request_prefix=False, relay_server=None, relay_address=None):
        """
        DHCPv6 클라이언트 초기화

        Args:
            interface: 네트워크 인터페이스 이름
            client_id: 클라이언트 ID (None이면 자동 생성)
            request_prefix: Prefix Delegation 요청 여부
            relay_server: Relay 모드 사용 시 DHCPv6 서버 주소 (None이면 일반 모드)
            relay_address: Relay Agent 주소 (기본값: "::")
        """
        self.interface = interface
        self.request_prefix = request_prefix
        self.client_id = client_id or f"client-{uuid.uuid4().hex[:8]}"
        self.relay_server = relay_server
        self.relay_address = relay_address
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

        # 재전송 타이머 관리 (RFC 8415)
        self.retransmit_timer = None
        self.retry_count = 0
        self.current_rt = 0

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
        if self.retransmit_timer:
            self.retransmit_timer.cancel()

        if self.recv_thread:
            self.recv_thread.join(timeout=2)

    def _send_solicit(self):
        """SOLICIT 메시지 전송"""
        mode = "via Relay" if self.relay_server else "multicast"
        self.logger.info(f"Sending SOLICIT message ({mode})")
        self.state = self.STATE_SOLICIT

        # 재전송 상태 초기화
        self._cancel_retransmit_timer()

        pkt = self.packet_builder.build_solicit(
            request_ia_na=True,
            request_ia_pd=self.request_prefix
        )

        try:
            # Link-local 주소 가져오기
            self._set_src_addr(pkt)

            # Relay 모드: RELAY-FORW로 감싸기
            if self.relay_server:
                peer_addr = pkt[IPv6].src if pkt.haslayer(IPv6) else None
                pkt = self.packet_builder.build_relay_forward(
                    client_message=pkt,
                    server_address=self.relay_server,
                    relay_address=self.relay_address,
                    peer_address=peer_addr
                )
                self._set_src_addr(pkt)
                self.logger.debug(f"SOLICIT wrapped in RELAY-FORW to {self.relay_server}")

            # L2 레벨 전송 (Ether 헤더 추가)
            pkt_l2 = self._add_ether_header(pkt)
            sendp(pkt_l2, iface=self.interface, verbose=False)
            self.logger.debug("SOLICIT sent successfully")

            # 재전송 타이머 스케줄 (RFC 8415)
            rt = self._calculate_retransmission_time(self.SOL_TIMEOUT, self.SOL_MAX_RT)
            self.retransmit_timer = threading.Timer(rt, self._retransmit_solicit)
            self.retransmit_timer.start()
            self.logger.debug(f"SOLICIT retransmission scheduled in {rt:.1f}s")

        except Exception as e:
            self.logger.error(f"Failed to send SOLICIT: {e}")

    def _send_request(self):
        """REQUEST 메시지 전송"""
        mode = "via Relay" if self.relay_server else "multicast"
        self.logger.info(f"Sending REQUEST message ({mode})")
        self.state = self.STATE_REQUEST

        # 재전송 상태 초기화
        self._cancel_retransmit_timer()

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

            # Relay 모드: RELAY-FORW로 감싸기
            if self.relay_server:
                peer_addr = pkt[IPv6].src if pkt.haslayer(IPv6) else None
                pkt = self.packet_builder.build_relay_forward(
                    client_message=pkt,
                    server_address=self.relay_server,
                    relay_address=self.relay_address,
                    peer_address=peer_addr
                )
                self._set_src_addr(pkt)
                self.logger.debug(f"REQUEST wrapped in RELAY-FORW to {self.relay_server}")

            # L2 레벨 전송 (Ether 헤더 추가)
            pkt_l2 = self._add_ether_header(pkt)
            sendp(pkt_l2, iface=self.interface, verbose=False)
            self.logger.debug("REQUEST sent successfully")

            # 재전송 타이머 스케줄 (RFC 8415)
            rt = self._calculate_retransmission_time(self.REQ_TIMEOUT, self.REQ_MAX_RT)
            self.retransmit_timer = threading.Timer(rt, self._retransmit_request)
            self.retransmit_timer.start()
            self.logger.debug(f"REQUEST retransmission scheduled in {rt:.1f}s")

        except Exception as e:
            self.logger.error(f"Failed to send REQUEST: {e}")

    def _send_renew(self):
        """RENEW 메시지 전송"""
        mode = "via Relay" if self.relay_server else "multicast"
        self.logger.info(f"Sending RENEW message ({mode})")
        self.state = self.STATE_RENEW

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

            # Relay 모드: RELAY-FORW로 감싸기
            if self.relay_server:
                peer_addr = pkt[IPv6].src if pkt.haslayer(IPv6) else None
                pkt = self.packet_builder.build_relay_forward(
                    client_message=pkt,
                    server_address=self.relay_server,
                    relay_address=self.relay_address,
                    peer_address=peer_addr
                )
                self._set_src_addr(pkt)
                self.logger.debug(f"RENEW wrapped in RELAY-FORW to {self.relay_server}")

            # L2 레벨 전송 (Ether 헤더 추가)
            pkt_l2 = self._add_ether_header(pkt)
            sendp(pkt_l2, iface=self.interface, verbose=False)
            self.logger.debug("RENEW sent successfully")
        except Exception as e:
            self.logger.error(f"Failed to send RENEW: {e}")

    def _send_rebind(self):
        """REBIND 메시지 전송"""
        self.logger.info("Sending REBIND message")
        self.state = self.STATE_REBIND

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
            # L2 레벨 전송 (Ether 헤더 추가)
            pkt_l2 = self._add_ether_header(pkt)
            sendp(pkt_l2, iface=self.interface, verbose=False)
            self.logger.debug("REBIND sent successfully")
        except Exception as e:
            self.logger.error(f"Failed to send REBIND: {e}")

    def _recv_packets(self):
        """DHCPv6 패킷 수신 스레드"""
        def packet_handler(pkt):
            if not self.running:
                return

            # Python 레벨 필터링 (libpcap BPF 컴파일 우회)
            if not pkt.haslayer(UDP):
                return
            if pkt[UDP].dport != DHCPV6_CLIENT_PORT:
                return

            try:
                self._handle_packet(pkt)
            except Exception as e:
                self.logger.error(f"Error handling packet: {e}")

        self.logger.debug(f"Starting packet capture (DHCPv6 client port {DHCPV6_CLIENT_PORT})")
        sniff(
            iface=self.interface,
            filter=None,  # BPF 필터 제거 (Python 레벨에서 필터링)
            prn=packet_handler,
            store=False,
            stop_filter=lambda x: not self.running
        )

    def _handle_packet(self, pkt):
        """수신한 DHCPv6 패킷 처리"""
        # Relay 모드: RELAY-REPL에서 원본 메시지 추출
        if self.relay_server and pkt.haslayer(DHCP6_RelayReply):
            self.logger.debug("Received RELAY-REPL, extracting original message")
            original_pkt = DHCPv6Packet.parse_relay_reply(pkt)
            if original_pkt:
                # 원본 패킷으로 교체
                pkt = original_pkt
            else:
                self.logger.warning("Failed to extract message from RELAY-REPL")
                return

        # 일반 메시지 처리
        if pkt.haslayer(DHCP6_Advertise) and self.state == self.STATE_SOLICIT:
            self._handle_advertise(pkt)
        elif pkt.haslayer(DHCP6_Reply):
            if self.state == self.STATE_REQUEST:
                self._handle_reply(pkt)
            elif self.state == self.STATE_RENEW:
                self._handle_renew_reply(pkt)
            elif self.state == self.STATE_REBIND:
                self._handle_rebind_reply(pkt)

    def _handle_advertise(self, pkt):
        """ADVERTISE 메시지 처리"""
        self.logger.info("Received ADVERTISE message")

        # 재전송 타이머 취소
        self._cancel_retransmit_timer()

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

        # 재전송 타이머 취소
        self._cancel_retransmit_timer()

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

    def _add_ether_header(self, pkt):
        """
        IPv6 패킷에 Ether 헤더 추가 (L2 전송용)

        Args:
            pkt: IPv6 패킷

        Returns:
            Ether/IPv6 패킷
        """
        # DHCPv6 멀티캐스트 주소 ff02::1:2의 MAC 주소: 33:33:00:01:00:02
        if pkt.haslayer(IPv6):
            dst_ip = pkt[IPv6].dst
            if dst_ip.startswith("ff02::1:2"):
                # DHCPv6 멀티캐스트 MAC
                dst_mac = "33:33:00:01:00:02"
            elif dst_ip.startswith("ff"):
                # 일반 IPv6 멀티캐스트 MAC 계산
                # ff02::1:2 → 33:33:00:01:00:02
                ipv6_suffix = dst_ip.split(":")[-2:]
                mac_suffix = ":".join([f"{int(x, 16):02x}" for x in ipv6_suffix if x])
                dst_mac = f"33:33:{mac_suffix}" if mac_suffix else "33:33:00:01:00:02"
            else:
                # 유니캐스트 - NDP로 MAC 주소 찾기 (간단히 브로드캐스트 사용)
                dst_mac = "ff:ff:ff:ff:ff:ff"
        else:
            dst_mac = "ff:ff:ff:ff:ff:ff"

        # Ether 헤더 추가
        return Ether(dst=dst_mac) / pkt

    def get_status(self):
        """클라이언트 상태 정보 반환"""
        return {
            'client_id': self.client_id,
            'state': self.state,
            'addresses': self.assigned_addresses,
            'prefixes': self.assigned_prefixes,
            'server_duid': self.server_duid.hex() if self.server_duid else None
        }

    def _calculate_retransmission_time(self, irt, mrt):
        """
        RFC 8415 Exponential Backoff 재전송 시간 계산

        Args:
            irt: 초기 재전송 타임아웃
            mrt: 최대 재전송 타임아웃

        Returns:
            다음 재전송까지의 시간 (초)
        """
        import random

        if self.retry_count == 0:
            # 첫 전송
            rt = irt
        else:
            # Exponential backoff: RT = 2*RTprev + RAND*RTprev
            # RAND는 -0.1 ~ +0.1 범위
            rand = random.uniform(-0.1, 0.1)
            rt = 2 * self.current_rt + rand * self.current_rt

        # MRT 제한
        if rt > mrt:
            rand = random.uniform(-0.1, 0.1)
            rt = mrt + rand * mrt

        # 음수 방지
        rt = max(0.1, rt)

        self.current_rt = rt
        return rt

    def _cancel_retransmit_timer(self):
        """재전송 타이머 취소"""
        if self.retransmit_timer:
            self.retransmit_timer.cancel()
            self.retransmit_timer = None
        self.retry_count = 0
        self.current_rt = 0

    def _retransmit_solicit(self):
        """SOLICIT 재전송 (RFC 8415)"""
        if not self.running or self.state != self.STATE_SOLICIT:
            return

        self.retry_count += 1
        rt = self._calculate_retransmission_time(self.SOL_TIMEOUT, self.SOL_MAX_RT)

        self.logger.info(f"Retransmitting SOLICIT (attempt {self.retry_count}, next in {rt:.1f}s)")

        # SOLICIT 재전송
        pkt = self.packet_builder.build_solicit(
            request_ia_na=True,
            request_ia_pd=self.request_prefix
        )

        try:
            self._set_src_addr(pkt)

            # Relay 모드: RELAY-FORW로 감싸기
            if self.relay_server:
                peer_addr = pkt[IPv6].src if pkt.haslayer(IPv6) else None
                pkt = self.packet_builder.build_relay_forward(
                    client_message=pkt,
                    server_address=self.relay_server,
                    relay_address=self.relay_address,
                    peer_address=peer_addr
                )
                self._set_src_addr(pkt)

            # L2 레벨 전송 (Ether 헤더 추가)
            pkt_l2 = self._add_ether_header(pkt)
            sendp(pkt_l2, iface=self.interface, verbose=False)

            # 다음 재전송 스케줄 (무제한)
            self.retransmit_timer = threading.Timer(rt, self._retransmit_solicit)
            self.retransmit_timer.start()

        except Exception as e:
            self.logger.error(f"Failed to retransmit SOLICIT: {e}")

    def _retransmit_request(self):
        """REQUEST 재전송 (RFC 8415)"""
        if not self.running or self.state != self.STATE_REQUEST:
            return

        # 최대 재시도 횟수 확인
        if self.retry_count >= self.REQ_MAX_RC:
            self.logger.warning(f"REQUEST max retries ({self.REQ_MAX_RC}) reached, giving up")
            self._cancel_retransmit_timer()
            # SOLICIT으로 되돌아가기
            self.logger.info("Falling back to SOLICIT")
            self._send_solicit()
            return

        self.retry_count += 1
        rt = self._calculate_retransmission_time(self.REQ_TIMEOUT, self.REQ_MAX_RT)

        self.logger.info(f"Retransmitting REQUEST (attempt {self.retry_count}/{self.REQ_MAX_RC}, next in {rt:.1f}s)")

        # REQUEST 재전송
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

            # Relay 모드: RELAY-FORW로 감싸기
            if self.relay_server:
                peer_addr = pkt[IPv6].src if pkt.haslayer(IPv6) else None
                pkt = self.packet_builder.build_relay_forward(
                    client_message=pkt,
                    server_address=self.relay_server,
                    relay_address=self.relay_address,
                    peer_address=peer_addr
                )
                self._set_src_addr(pkt)

            # L2 레벨 전송 (Ether 헤더 추가)
            pkt_l2 = self._add_ether_header(pkt)
            sendp(pkt_l2, iface=self.interface, verbose=False)

            # 다음 재전송 스케줄
            self.retransmit_timer = threading.Timer(rt, self._retransmit_request)
            self.retransmit_timer.start()

        except Exception as e:
            self.logger.error(f"Failed to retransmit REQUEST: {e}")
