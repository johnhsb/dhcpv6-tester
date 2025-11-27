"""DHCPv6 서버 구현"""

import time
import threading
import logging
import ipaddress
from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.dhcp6 import *
from scapy.layers.l2 import Ether
from dhcpv6_packet import DHCPv6Packet, DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class DHCPv6Server:
    """DHCPv6 서버"""

    def __init__(self, interface, address_pool="2001:db8:1::/64",
                 prefix_pool="2001:db8:2::/48", prefix_length=56,
                 valid_lifetime=7200, preferred_lifetime=3600,
                 max_addresses=10000, max_prefixes=1000):
        """
        DHCPv6 서버 초기화

        Args:
            interface: 네트워크 인터페이스 이름
            address_pool: 할당할 주소 풀 (CIDR)
            prefix_pool: Prefix Delegation 풀 (CIDR)
            prefix_length: 위임할 prefix 길이
            valid_lifetime: Valid lifetime (초)
            preferred_lifetime: Preferred lifetime (초)
            max_addresses: 최대 할당 가능 주소 수 (메모리 보호)
            max_prefixes: 최대 할당 가능 prefix 수 (메모리 보호)
        """
        self.interface = interface
        self.logger = logging.getLogger("DHCPv6Server")

        # 주소 풀 설정 (on-demand 생성을 위해 네트워크 객체만 저장)
        self.address_network = ipaddress.IPv6Network(address_pool)
        self.next_address_index = 0
        self.max_addresses = max_addresses

        # Prefix 풀 설정 (on-demand 생성)
        self.prefix_network = ipaddress.IPv6Network(prefix_pool)
        self.prefix_length = prefix_length
        self.next_prefix_index = 0
        self.max_prefixes = max_prefixes

        # Lifetime 설정
        self.valid_lifetime = valid_lifetime
        self.preferred_lifetime = preferred_lifetime

        # 서버 DUID 생성
        self.packet_builder = DHCPv6Packet()
        self.server_duid = self.packet_builder._generate_duid()

        # 할당 추적 (client_duid -> {addresses, prefixes, timestamp})
        self.leases = {}
        self.lease_lock = threading.Lock()

        # 패킷 수신 스레드
        self.running = False
        self.recv_thread = None
        self.cleanup_thread = None

        # 통계
        self.stats = {
            'solicit_received': 0,
            'advertise_sent': 0,
            'request_received': 0,
            'reply_sent': 0,
            'renew_received': 0,
            'rebind_received': 0,
            'total_addresses_allocated': 0,
            'total_prefixes_allocated': 0,
        }
        self.stats_lock = threading.Lock()

    def start(self):
        """서버 시작"""
        self.logger.info(f"Starting DHCPv6 server on interface {self.interface}")
        self.logger.info(f"Address pool: {self.address_network} (max: {self.max_addresses})")
        self.logger.info(f"Prefix pool: {self.prefix_network} (/{self.prefix_length}, max: {self.max_prefixes})")
        self.logger.info(f"Server DUID: {self.server_duid.hex()}")

        self.running = True

        # 패킷 수신 스레드 시작
        self.recv_thread = threading.Thread(target=self._recv_packets, daemon=True)
        self.recv_thread.start()

        # Lease 정리 스레드 시작
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_leases, daemon=True)
        self.cleanup_thread.start()

    def stop(self):
        """서버 중지"""
        self.logger.info("Stopping DHCPv6 server")
        self.running = False

        if self.recv_thread:
            self.recv_thread.join(timeout=2)

        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=2)

    def _allocate_address(self):
        """주소 풀에서 다음 주소 할당 (on-demand 생성)"""
        if self.next_address_index >= self.max_addresses:
            self.logger.warning("Address pool exhausted (max limit reached)!")
            return None

        # 필요할 때만 주소 생성 (메모리 효율적)
        # network_address + 1부터 시작 (network_address 자체는 네트워크 주소)
        addr = self.address_network.network_address + self.next_address_index + 1
        self.next_address_index += 1
        return str(addr)

    def _allocate_prefix(self):
        """Prefix 풀에서 다음 prefix 할당 (on-demand 생성)"""
        # 가능한 총 prefix 개수 계산
        prefix_bits = self.prefix_length - self.prefix_network.prefixlen
        total_prefixes = 2 ** prefix_bits

        if self.next_prefix_index >= min(total_prefixes, self.max_prefixes):
            self.logger.warning("Prefix pool exhausted!")
            return None

        # 비트 연산으로 N번째 서브넷 주소 계산 (메모리 효율적)
        offset = self.next_prefix_index << (128 - self.prefix_length)
        prefix_addr = self.prefix_network.network_address + offset
        self.next_prefix_index += 1

        return (str(prefix_addr), self.prefix_length)

    def _cleanup_expired_leases(self):
        """만료된 lease 주기적으로 정리 (메모리 누수 방지)"""
        self.logger.info("Lease cleanup thread started")

        while self.running:
            time.sleep(60)  # 1분마다 정리

            if not self.running:
                break

            with self.lease_lock:
                current_time = time.time()
                expired_duids = []

                # 만료된 lease 찾기
                for client_duid, lease_info in self.leases.items():
                    lease_age = current_time - lease_info['timestamp']
                    if lease_age > self.valid_lifetime:
                        expired_duids.append(client_duid)

                # 만료된 lease 제거
                for duid in expired_duids:
                    del self.leases[duid]
                    self.logger.debug(f"Cleaned up expired lease: {duid[:16]}...")

                if expired_duids:
                    self.logger.info(f"Cleaned up {len(expired_duids)} expired lease(s)")

        self.logger.info("Lease cleanup thread stopped")

    def _recv_packets(self):
        """DHCPv6 패킷 수신 스레드"""
        def packet_handler(pkt):
            if not self.running:
                return

            # Python 레벨 필터링
            if not pkt.haslayer(UDP):
                return
            if pkt[UDP].dport != DHCPV6_SERVER_PORT:
                return

            try:
                self._handle_packet(pkt)
            except Exception as e:
                self.logger.error(f"Error handling packet: {e}", exc_info=True)

        self.logger.debug(f"Starting packet capture (DHCPv6 server port {DHCPV6_SERVER_PORT})")
        sniff(
            iface=self.interface,
            filter=None,  # Python 레벨 필터링
            prn=packet_handler,
            store=False,
            stop_filter=lambda x: not self.running
        )

    def _handle_packet(self, pkt):
        """수신한 DHCPv6 패킷 처리"""
        # Relay 메시지 처리
        if pkt.haslayer(DHCP6_RelayForward):
            self._handle_relay_forward(pkt)
            return

        # 일반 DHCPv6 메시지 처리
        if pkt.haslayer(DHCP6_Solicit):
            self._handle_solicit(pkt)
        elif pkt.haslayer(DHCP6_Request):
            self._handle_request(pkt)
        elif pkt.haslayer(DHCP6_Renew):
            self._handle_renew(pkt)
        elif pkt.haslayer(DHCP6_Rebind):
            self._handle_rebind(pkt)

    def _handle_solicit(self, pkt):
        """SOLICIT 메시지 처리 → ADVERTISE 전송"""
        self.logger.info("Received SOLICIT message")

        with self.stats_lock:
            self.stats['solicit_received'] += 1

        # 클라이언트 정보 추출
        if not pkt.haslayer(DHCP6OptClientId):
            self.logger.warning("SOLICIT without client ID")
            return

        client_duid = pkt[DHCP6OptClientId].duid

        # DHCP6_Solicit 레이어가 없으면 DHCP6 레이어 사용 (RELAY-FORW 처리용)
        dhcp6_layer = pkt[DHCP6_Solicit] if pkt.haslayer(DHCP6_Solicit) else pkt[DHCP6]
        transaction_id = dhcp6_layer.trid

        # IA_NA 요청 확인
        request_ia_na = pkt.haslayer(DHCP6OptIA_NA)
        request_ia_pd = pkt.haslayer(DHCP6OptIA_PD)

        # 주소/Prefix 할당
        addresses = []
        prefixes = []

        if request_ia_na:
            addr = self._allocate_address()
            if addr:
                addresses.append({
                    'address': addr,
                    'preferred_lifetime': self.preferred_lifetime,
                    'valid_lifetime': self.valid_lifetime
                })

        if request_ia_pd:
            prefix_info = self._allocate_prefix()
            if prefix_info:
                prefix, plen = prefix_info
                prefixes.append({
                    'prefix': prefix,
                    'prefix_length': plen,
                    'preferred_lifetime': self.preferred_lifetime,
                    'valid_lifetime': self.valid_lifetime
                })

        # ADVERTISE 전송
        self._send_advertise(pkt, transaction_id, addresses, prefixes)

    def _send_advertise(self, original_pkt, transaction_id, addresses, prefixes):
        """ADVERTISE 메시지 전송"""
        # ADVERTISE 메시지 생성
        dhcp6_msg = DHCP6_Advertise(trid=transaction_id)

        # Server Identifier
        dhcp6_msg /= DHCP6OptServerId(duid=self.server_duid)

        # Client Identifier (원본에서 복사)
        if original_pkt.haslayer(DHCP6OptClientId):
            dhcp6_msg /= DHCP6OptClientId(duid=original_pkt[DHCP6OptClientId].duid)

        # IA_NA with addresses
        if addresses and original_pkt.haslayer(DHCP6OptIA_NA):
            iaid = original_pkt[DHCP6OptIA_NA].iaid
            ia_na = DHCP6OptIA_NA(
                iaid=iaid,
                T1=int(self.valid_lifetime * 0.5),
                T2=int(self.valid_lifetime * 0.8)
            )
            for addr_info in addresses:
                ia_addr = DHCP6OptIAAddress(
                    addr=addr_info['address'],
                    preflft=addr_info['preferred_lifetime'],
                    validlft=addr_info['valid_lifetime']
                )
                ia_na /= ia_addr
            dhcp6_msg /= ia_na

        # IA_PD with prefixes
        if prefixes and original_pkt.haslayer(DHCP6OptIA_PD):
            iaid = original_pkt[DHCP6OptIA_PD].iaid
            ia_pd = DHCP6OptIA_PD(
                iaid=iaid,
                T1=int(self.valid_lifetime * 0.5),
                T2=int(self.valid_lifetime * 0.8)
            )
            for prefix_info in prefixes:
                ia_prefix = DHCP6OptIAPrefix(
                    prefix=prefix_info['prefix'],
                    plen=prefix_info['prefix_length'],
                    preflft=prefix_info['preferred_lifetime'],
                    validlft=prefix_info['valid_lifetime']
                )
                ia_pd /= ia_prefix
            dhcp6_msg /= ia_pd

        # IPv6/UDP 헤더 (멀티캐스트로 응답)
        src_addr = self._get_link_local_address()
        pkt = IPv6(src=src_addr, dst="ff02::1:2") / UDP(sport=DHCPV6_SERVER_PORT, dport=DHCPV6_CLIENT_PORT) / dhcp6_msg

        # L2 전송
        pkt_l2 = Ether(dst="33:33:00:01:00:02") / pkt
        sendp(pkt_l2, iface=self.interface, verbose=False)

        self.logger.info(f"Sent ADVERTISE: {len(addresses)} address(es), {len(prefixes)} prefix(es)")

        with self.stats_lock:
            self.stats['advertise_sent'] += 1

    def _handle_request(self, pkt):
        """REQUEST 메시지 처리 → REPLY 전송 (주소 할당 확정)"""
        self.logger.info("Received REQUEST message")

        with self.stats_lock:
            self.stats['request_received'] += 1

        # 클라이언트 정보 추출
        if not pkt.haslayer(DHCP6OptClientId):
            return

        client_duid = pkt[DHCP6OptClientId].duid

        # DHCP6_Request 레이어가 없으면 DHCP6 레이어 사용 (RELAY-FORW 처리용)
        dhcp6_layer = pkt[DHCP6_Request] if pkt.haslayer(DHCP6_Request) else pkt[DHCP6]
        transaction_id = dhcp6_layer.trid

        # 요청된 주소/Prefix 추출
        addresses = []
        prefixes = []

        if pkt.haslayer(DHCP6OptIA_NA):
            ia_na = pkt[DHCP6OptIA_NA]
            if ia_na.haslayer(DHCP6OptIAAddress):
                for opt in ia_na.iterpayloads():
                    if isinstance(opt, DHCP6OptIAAddress):
                        addresses.append({
                            'address': opt.addr,
                            'preferred_lifetime': self.preferred_lifetime,
                            'valid_lifetime': self.valid_lifetime
                        })

        if pkt.haslayer(DHCP6OptIA_PD):
            ia_pd = pkt[DHCP6OptIA_PD]
            if ia_pd.haslayer(DHCP6OptIAPrefix):
                for opt in ia_pd.iterpayloads():
                    if isinstance(opt, DHCP6OptIAPrefix):
                        prefixes.append({
                            'prefix': opt.prefix,
                            'prefix_length': opt.plen,
                            'preferred_lifetime': self.preferred_lifetime,
                            'valid_lifetime': self.valid_lifetime
                        })

        # Lease 저장
        with self.lease_lock:
            self.leases[client_duid.hex()] = {
                'addresses': addresses,
                'prefixes': prefixes,
                'timestamp': time.time()
            }

            with self.stats_lock:
                self.stats['total_addresses_allocated'] += len(addresses)
                self.stats['total_prefixes_allocated'] += len(prefixes)

        # REPLY 전송
        self._send_reply(pkt, transaction_id, addresses, prefixes)

    def _handle_renew(self, pkt):
        """RENEW 메시지 처리 → REPLY 전송 (갱신)"""
        self.logger.info("Received RENEW message")

        with self.stats_lock:
            self.stats['renew_received'] += 1

        # REQUEST와 동일하게 처리
        if not pkt.haslayer(DHCP6OptClientId):
            return

        # DHCP6_Renew 레이어가 없으면 DHCP6 레이어 사용 (RELAY-FORW 처리용)
        dhcp6_layer = pkt[DHCP6_Renew] if pkt.haslayer(DHCP6_Renew) else pkt[DHCP6]
        transaction_id = dhcp6_layer.trid

        # 기존 주소/Prefix 갱신
        addresses = []
        prefixes = []

        if pkt.haslayer(DHCP6OptIA_NA):
            ia_na = pkt[DHCP6OptIA_NA]
            if ia_na.haslayer(DHCP6OptIAAddress):
                for opt in ia_na.iterpayloads():
                    if isinstance(opt, DHCP6OptIAAddress):
                        addresses.append({
                            'address': opt.addr,
                            'preferred_lifetime': self.preferred_lifetime,
                            'valid_lifetime': self.valid_lifetime
                        })

        if pkt.haslayer(DHCP6OptIA_PD):
            ia_pd = pkt[DHCP6OptIA_PD]
            if ia_pd.haslayer(DHCP6OptIAPrefix):
                for opt in ia_pd.iterpayloads():
                    if isinstance(opt, DHCP6OptIAPrefix):
                        prefixes.append({
                            'prefix': opt.prefix,
                            'prefix_length': opt.plen,
                            'preferred_lifetime': self.preferred_lifetime,
                            'valid_lifetime': self.valid_lifetime
                        })

        self._send_reply(pkt, transaction_id, addresses, prefixes)

    def _handle_rebind(self, pkt):
        """REBIND 메시지 처리 → REPLY 전송"""
        self.logger.info("Received REBIND message")

        with self.stats_lock:
            self.stats['rebind_received'] += 1

        # RENEW와 동일하게 처리
        self._handle_renew(pkt)

    def _send_reply(self, original_pkt, transaction_id, addresses, prefixes):
        """REPLY 메시지 전송"""
        # REPLY 메시지 생성
        dhcp6_msg = DHCP6_Reply(trid=transaction_id)

        # Server Identifier
        dhcp6_msg /= DHCP6OptServerId(duid=self.server_duid)

        # Client Identifier
        if original_pkt.haslayer(DHCP6OptClientId):
            dhcp6_msg /= DHCP6OptClientId(duid=original_pkt[DHCP6OptClientId].duid)

        # IA_NA
        if addresses and original_pkt.haslayer(DHCP6OptIA_NA):
            iaid = original_pkt[DHCP6OptIA_NA].iaid
            ia_na = DHCP6OptIA_NA(
                iaid=iaid,
                T1=int(self.valid_lifetime * 0.5),
                T2=int(self.valid_lifetime * 0.8)
            )
            for addr_info in addresses:
                ia_addr = DHCP6OptIAAddress(
                    addr=addr_info['address'],
                    preflft=addr_info['preferred_lifetime'],
                    validlft=addr_info['valid_lifetime']
                )
                ia_na /= ia_addr
            dhcp6_msg /= ia_na

        # IA_PD
        if prefixes and original_pkt.haslayer(DHCP6OptIA_PD):
            iaid = original_pkt[DHCP6OptIA_PD].iaid
            ia_pd = DHCP6OptIA_PD(
                iaid=iaid,
                T1=int(self.valid_lifetime * 0.5),
                T2=int(self.valid_lifetime * 0.8)
            )
            for prefix_info in prefixes:
                ia_prefix = DHCP6OptIAPrefix(
                    prefix=prefix_info['prefix'],
                    plen=prefix_info['prefix_length'],
                    preflft=prefix_info['preferred_lifetime'],
                    validlft=prefix_info['valid_lifetime']
                )
                ia_pd /= ia_prefix
            dhcp6_msg /= ia_pd

        # IPv6/UDP 헤더
        src_addr = self._get_link_local_address()
        pkt = IPv6(src=src_addr, dst="ff02::1:2") / UDP(sport=DHCPV6_SERVER_PORT, dport=DHCPV6_CLIENT_PORT) / dhcp6_msg

        # L2 전송
        pkt_l2 = Ether(dst="33:33:00:01:00:02") / pkt
        sendp(pkt_l2, iface=self.interface, verbose=False)

        self.logger.info(f"Sent REPLY: {len(addresses)} address(es), {len(prefixes)} prefix(es)")

        with self.stats_lock:
            self.stats['reply_sent'] += 1

    def _handle_relay_forward(self, pkt):
        """RELAY-FORW 메시지 처리"""
        self.logger.debug("Received RELAY-FORW message")

        # Relay Message Option에서 원본 클라이언트 메시지 추출
        if not pkt.haslayer(DHCP6OptRelayMsg):
            self.logger.warning("RELAY-FORW without DHCP6OptRelayMsg")
            return

        relay_msg_opt = pkt[DHCP6OptRelayMsg]

        # relay_msg_opt.message는 이미 파싱된 DHCPv6 객체
        # bytes로 변환 후 다시 파싱
        if hasattr(relay_msg_opt, 'message'):
            # message가 이미 Packet 객체인 경우 bytes로 변환
            if hasattr(relay_msg_opt.message, '__bytes__'):
                client_msg = DHCP6(bytes(relay_msg_opt.message))
            else:
                # 이미 파싱된 객체를 그대로 사용
                client_msg = relay_msg_opt.message
        else:
            self.logger.warning("RELAY-FORW without message option")
            return

        # 원본 클라이언트 메시지를 IPv6 패킷으로 재구성
        src_addr = self._get_link_local_address()
        client_pkt = IPv6(src=src_addr, dst="ff02::1:2") / UDP(sport=DHCPV6_SERVER_PORT, dport=DHCPV6_CLIENT_PORT) / client_msg

        # 클라이언트 메시지 타입에 따라 직접 핸들러 호출 (재귀 방지)
        # msgtype 필드로 메시지 타입 확인 (레이어 타입이 아닌 msgtype 값으로 판별)
        # DHCPv6 메시지 타입: 1=SOLICIT, 3=REQUEST, 5=RENEW, 6=REBIND
        if client_msg.haslayer(DHCP6_Solicit) or (hasattr(client_msg, 'msgtype') and client_msg.msgtype == 1):
            self.logger.debug("Extracted SOLICIT from RELAY-FORW")
            self._handle_solicit(client_pkt)
        elif client_msg.haslayer(DHCP6_Request) or (hasattr(client_msg, 'msgtype') and client_msg.msgtype == 3):
            self.logger.debug("Extracted REQUEST from RELAY-FORW")
            self._handle_request(client_pkt)
        elif client_msg.haslayer(DHCP6_Renew) or (hasattr(client_msg, 'msgtype') and client_msg.msgtype == 5):
            self.logger.debug("Extracted RENEW from RELAY-FORW")
            self._handle_renew(client_pkt)
        elif client_msg.haslayer(DHCP6_Rebind) or (hasattr(client_msg, 'msgtype') and client_msg.msgtype == 6):
            self.logger.debug("Extracted REBIND from RELAY-FORW")
            self._handle_rebind(client_pkt)
        else:
            msgtype = getattr(client_msg, 'msgtype', 'unknown')
            self.logger.warning(f"Unknown message type in RELAY-FORW: msgtype={msgtype}, {client_msg.summary()}")

        # TODO: 실제로는 RELAY-REPL로 응답해야 함 (현재는 직접 클라이언트에게 응답)

    def _get_link_local_address(self):
        """인터페이스의 link-local 주소 가져오기"""
        try:
            import netifaces
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET6 in addrs:
                for addr_info in addrs[netifaces.AF_INET6]:
                    addr = addr_info['addr'].split('%')[0]
                    if addr.startswith('fe80:'):
                        return addr
        except Exception as e:
            self.logger.warning(f"Could not get link-local address: {e}")

        return "fe80::1"  # 기본값

    def get_stats(self):
        """서버 통계 반환"""
        with self.stats_lock:
            stats = self.stats.copy()

        # 메모리 사용량 추가
        try:
            import psutil
            process = psutil.Process()
            stats['memory_mb'] = process.memory_info().rss / 1024 / 1024
        except ImportError:
            stats['memory_mb'] = None
        except Exception as e:
            self.logger.warning(f"Failed to get memory info: {e}")
            stats['memory_mb'] = None

        return stats

    def get_leases(self):
        """현재 Lease 정보 반환"""
        with self.lease_lock:
            return self.leases.copy()
