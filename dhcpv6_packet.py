"""DHCPv6 패킷 생성 및 파싱 모듈"""

import struct
import random
import uuid
from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.dhcp6 import *

# DHCPv6 Message Types
DHCPV6_SOLICIT = 1
DHCPV6_ADVERTISE = 2
DHCPV6_REQUEST = 3
DHCPV6_CONFIRM = 4
DHCPV6_RENEW = 5
DHCPV6_REBIND = 6
DHCPV6_REPLY = 7
DHCPV6_RELEASE = 8
DHCPV6_DECLINE = 9
DHCPV6_RELAY_FORW = 12
DHCPV6_RELAY_REPL = 13

# DHCPv6 Option Types
OPTION_CLIENTID = 1
OPTION_SERVERID = 2
OPTION_IA_NA = 3
OPTION_IA_TA = 4
OPTION_IAADDR = 5
OPTION_ORO = 6
OPTION_ELAPSED_TIME = 8
OPTION_RELAY_MSG = 9
OPTION_IA_PD = 25
OPTION_IAPREFIX = 26

# DHCPv6 Ports
DHCPV6_CLIENT_PORT = 546
DHCPV6_SERVER_PORT = 547

# DHCPv6 Multicast Address
ALL_DHCP_RELAY_AGENTS_AND_SERVERS = "ff02::1:2"


class DHCPv6Packet:
    """DHCPv6 패킷 생성 클래스"""

    def __init__(self, client_mac=None, client_duid=None):
        """
        DHCPv6 패킷 빌더 초기화

        Args:
            client_mac: 클라이언트 MAC 주소 (None이면 랜덤 생성)
            client_duid: 클라이언트 DUID (None이면 자동 생성)
        """
        self.client_mac = client_mac or self._generate_random_mac()
        self.client_duid = client_duid or self._generate_duid()
        self.transaction_id = random.randint(0, 0xFFFFFF)
        self.iaid = random.randint(0, 0xFFFFFFFF)

    def _generate_random_mac(self):
        """랜덤 MAC 주소 생성"""
        mac = [0x00, 0x16, 0x3e,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x" % x, mac))

    def _generate_duid(self):
        """DUID-LLT (Link-layer address plus time) 생성"""
        # DUID Type: 1 (LLT)
        duid_type = struct.pack("!H", 1)
        # Hardware Type: 1 (Ethernet)
        hw_type = struct.pack("!H", 1)
        # Time (seconds since Jan 1, 2000)
        timestamp = struct.pack("!I", int(time.time()) - 946684800)
        # Link-layer address
        ll_addr = bytes.fromhex(self.client_mac.replace(':', ''))

        return duid_type + hw_type + timestamp + ll_addr

    def build_solicit(self, request_ia_na=True, request_ia_pd=False):
        """
        SOLICIT 메시지 생성

        Args:
            request_ia_na: IA_NA (주소) 요청 여부
            request_ia_pd: IA_PD (Prefix Delegation) 요청 여부

        Returns:
            scapy 패킷 객체
        """
        # 새로운 transaction ID 생성 (RFC 8415: 각 메시지마다 새 ID)
        self.transaction_id = random.randint(0, 0xFFFFFF)

        # DHCPv6 Solicit 메시지
        dhcp6_msg = DHCP6_Solicit(trid=self.transaction_id)

        # Client Identifier Option
        dhcp6_msg /= DHCP6OptClientId(duid=self.client_duid)

        # Elapsed Time Option
        dhcp6_msg /= DHCP6OptElapsedTime(elapsedtime=0)

        # IA_NA (Identity Association for Non-temporary Addresses)
        if request_ia_na:
            ia_na = DHCP6OptIA_NA(
                iaid=self.iaid,
                T1=0,
                T2=0
            )
            dhcp6_msg /= ia_na

        # IA_PD (Identity Association for Prefix Delegation)
        if request_ia_pd:
            ia_pd = DHCP6OptIA_PD(
                iaid=self.iaid + 1,
                T1=0,
                T2=0
            )
            dhcp6_msg /= ia_pd

        # Option Request Option (ORO)
        dhcp6_msg /= DHCP6OptOptReq(reqopts=[23, 24])  # DNS servers

        # IPv6 및 UDP 헤더 추가
        pkt = IPv6(dst=ALL_DHCP_RELAY_AGENTS_AND_SERVERS)
        pkt /= UDP(sport=DHCPV6_CLIENT_PORT, dport=DHCPV6_SERVER_PORT)
        pkt /= dhcp6_msg

        return pkt

    def build_request(self, server_duid, ia_na_addr=None, ia_pd_prefix=None,
                      ia_na_lifetime=None, ia_pd_lifetime=None):
        """
        REQUEST 메시지 생성

        Args:
            server_duid: 서버 DUID
            ia_na_addr: 요청할 IPv6 주소
            ia_pd_prefix: 요청할 Prefix (tuple: prefix, prefixlen)
            ia_na_lifetime: IA_NA lifetime (tuple: preferred, valid) - ADVERTISE에서 받은 값
            ia_pd_lifetime: IA_PD lifetime (tuple: preferred, valid) - ADVERTISE에서 받은 값

        Returns:
            scapy 패킷 객체
        """
        # 새로운 transaction ID 생성 (RFC 8415: 각 메시지마다 새 ID)
        self.transaction_id = random.randint(0, 0xFFFFFF)

        # DHCPv6 Request 메시지
        dhcp6_msg = DHCP6_Request(trid=self.transaction_id)

        # Client Identifier Option
        dhcp6_msg /= DHCP6OptClientId(duid=self.client_duid)

        # Server Identifier Option
        dhcp6_msg /= DHCP6OptServerId(duid=server_duid)

        # Elapsed Time Option
        dhcp6_msg /= DHCP6OptElapsedTime(elapsedtime=0)

        # IA_NA with requested address
        if ia_na_addr:
            # ADVERTISE에서 받은 lifetime 값 사용 (상용 서버 호환성)
            if ia_na_lifetime:
                preflft, validlft = ia_na_lifetime
            else:
                # fallback: ADVERTISE에서 값이 없으면 0 사용
                preflft, validlft = 0, 0

            ia_addr = DHCP6OptIAAddress(
                addr=ia_na_addr,
                preflft=preflft,
                validlft=validlft
            )
            # IA_NA 옵션 생성 시 ianaopts 필드에 직접 할당
            ia_na = DHCP6OptIA_NA(
                iaid=self.iaid,
                T1=0,
                T2=0,
                ianaopts=[ia_addr]  # 리스트로 직접 할당
            )
            dhcp6_msg /= ia_na

        # IA_PD with requested prefix
        if ia_pd_prefix:
            prefix, prefixlen = ia_pd_prefix
            # ADVERTISE에서 받은 lifetime 값 사용 (상용 서버 호환성)
            if ia_pd_lifetime:
                preflft, validlft = ia_pd_lifetime
            else:
                # fallback: ADVERTISE에서 값이 없으면 0 사용
                preflft, validlft = 0, 0

            ia_prefix = DHCP6OptIAPrefix(
                prefix=prefix,
                plen=prefixlen,
                preflft=preflft,
                validlft=validlft
            )
            # IA_PD 옵션 생성 시 iapdopt 필드에 직접 할당
            ia_pd = DHCP6OptIA_PD(
                iaid=self.iaid + 1,
                T1=0,
                T2=0,
                iapdopt=[ia_prefix]  # 리스트로 직접 할당
            )
            dhcp6_msg /= ia_pd

        # Option Request Option
        dhcp6_msg /= DHCP6OptOptReq(reqopts=[23, 24])

        # IPv6 및 UDP 헤더 추가
        pkt = IPv6(dst=ALL_DHCP_RELAY_AGENTS_AND_SERVERS)
        pkt /= UDP(sport=DHCPV6_CLIENT_PORT, dport=DHCPV6_SERVER_PORT)
        pkt /= dhcp6_msg

        return pkt

    def build_renew(self, server_duid, ia_na_addr=None, ia_pd_prefix=None):
        """
        RENEW 메시지 생성

        Args:
            server_duid: 서버 DUID
            ia_na_addr: 갱신할 IPv6 주소
            ia_pd_prefix: 갱신할 Prefix (tuple: prefix, prefixlen)

        Returns:
            scapy 패킷 객체
        """
        # 새로운 transaction ID 생성 (RFC 8415: 각 메시지마다 새 ID)
        self.transaction_id = random.randint(0, 0xFFFFFF)

        # DHCPv6 Renew 메시지
        dhcp6_msg = DHCP6_Renew(trid=self.transaction_id)

        # Client Identifier Option
        dhcp6_msg /= DHCP6OptClientId(duid=self.client_duid)

        # Server Identifier Option
        dhcp6_msg /= DHCP6OptServerId(duid=server_duid)

        # Elapsed Time Option
        dhcp6_msg /= DHCP6OptElapsedTime(elapsedtime=0)

        # IA_NA with address to renew
        if ia_na_addr:
            ia_addr = DHCP6OptIAAddress(
                addr=ia_na_addr,
                preflft=3600,
                validlft=7200
            )
            ia_na = DHCP6OptIA_NA(
                iaid=self.iaid,
                T1=0,
                T2=0,
                ianaopts=[ia_addr]
            )
            dhcp6_msg /= ia_na

        # IA_PD with prefix to renew
        if ia_pd_prefix:
            prefix, prefixlen = ia_pd_prefix
            ia_prefix = DHCP6OptIAPrefix(
                prefix=prefix,
                plen=prefixlen,
                preflft=3600,
                validlft=7200
            )
            ia_pd = DHCP6OptIA_PD(
                iaid=self.iaid + 1,
                T1=0,
                T2=0,
                iapdopt=[ia_prefix]
            )
            dhcp6_msg /= ia_pd

        # IPv6 및 UDP 헤더 추가
        pkt = IPv6(dst=ALL_DHCP_RELAY_AGENTS_AND_SERVERS)
        pkt /= UDP(sport=DHCPV6_CLIENT_PORT, dport=DHCPV6_SERVER_PORT)
        pkt /= dhcp6_msg

        return pkt

    def build_rebind(self, ia_na_addr=None, ia_pd_prefix=None):
        """
        REBIND 메시지 생성

        Args:
            ia_na_addr: 재바인딩할 IPv6 주소
            ia_pd_prefix: 재바인딩할 Prefix (tuple: prefix, prefixlen)

        Returns:
            scapy 패킷 객체
        """
        # 새로운 transaction ID 생성 (RFC 8415: 각 메시지마다 새 ID)
        self.transaction_id = random.randint(0, 0xFFFFFF)

        # DHCPv6 Rebind 메시지
        dhcp6_msg = DHCP6_Rebind(trid=self.transaction_id)

        # Client Identifier Option
        dhcp6_msg /= DHCP6OptClientId(duid=self.client_duid)

        # Elapsed Time Option
        dhcp6_msg /= DHCP6OptElapsedTime(elapsedtime=0)

        # IA_NA with address to rebind
        if ia_na_addr:
            ia_addr = DHCP6OptIAAddress(
                addr=ia_na_addr,
                preflft=3600,
                validlft=7200
            )
            ia_na = DHCP6OptIA_NA(
                iaid=self.iaid,
                T1=0,
                T2=0,
                ianaopts=[ia_addr]
            )
            dhcp6_msg /= ia_na

        # IA_PD with prefix to rebind
        if ia_pd_prefix:
            prefix, prefixlen = ia_pd_prefix
            ia_prefix = DHCP6OptIAPrefix(
                prefix=prefix,
                plen=prefixlen,
                preflft=3600,
                validlft=7200
            )
            ia_pd = DHCP6OptIA_PD(
                iaid=self.iaid + 1,
                T1=0,
                T2=0,
                iapdopt=[ia_prefix]
            )
            dhcp6_msg /= ia_pd

        # IPv6 및 UDP 헤더 추가
        pkt = IPv6(dst=ALL_DHCP_RELAY_AGENTS_AND_SERVERS)
        pkt /= UDP(sport=DHCPV6_CLIENT_PORT, dport=DHCPV6_SERVER_PORT)
        pkt /= dhcp6_msg

        return pkt

    @staticmethod
    def parse_reply(pkt):
        """
        DHCPv6 REPLY/ADVERTISE 메시지 파싱

        Args:
            pkt: scapy 패킷 객체

        Returns:
            dict: 파싱된 정보 (server_duid, addresses, prefixes 등)
        """
        result = {
            'msg_type': None,
            'server_duid': None,
            'addresses': [],
            'prefixes': [],
            'dns_servers': []
        }

        if not pkt.haslayer(DHCP6_Advertise) and not pkt.haslayer(DHCP6_Reply):
            return result

        # Message Type 확인
        if pkt.haslayer(DHCP6_Advertise):
            result['msg_type'] = 'ADVERTISE'
            dhcp6_layer = pkt[DHCP6_Advertise]
        else:
            result['msg_type'] = 'REPLY'
            dhcp6_layer = pkt[DHCP6_Reply]

        # Server DUID 추출
        if pkt.haslayer(DHCP6OptServerId):
            result['server_duid'] = bytes(pkt[DHCP6OptServerId].duid)

        # IA_NA 주소 추출
        if pkt.haslayer(DHCP6OptIA_NA):
            ia_na = pkt[DHCP6OptIA_NA]
            # IA_NA의 suboptions (ianaopts 필드)에서 IAAddress 추출
            # getlayer()를 사용하여 중첩된 옵션 순회
            addr_opt = ia_na.getlayer(DHCP6OptIAAddress)
            while addr_opt:
                result['addresses'].append({
                    'address': addr_opt.addr,
                    'preferred_lifetime': addr_opt.preflft,
                    'valid_lifetime': addr_opt.validlft
                })
                # 다음 IAAddress 옵션 찾기 (payload 체인에서)
                addr_opt = addr_opt.payload.getlayer(DHCP6OptIAAddress) if addr_opt.payload else None

        # IA_PD Prefix 추출
        if pkt.haslayer(DHCP6OptIA_PD):
            ia_pd = pkt[DHCP6OptIA_PD]
            # IA_PD의 suboptions (iapdopt 필드)에서 IAPrefix 추출
            # getlayer()를 사용하여 중첩된 옵션 순회
            prefix_opt = ia_pd.getlayer(DHCP6OptIAPrefix)
            while prefix_opt:
                result['prefixes'].append({
                    'prefix': prefix_opt.prefix,
                    'prefix_length': prefix_opt.plen,
                    'preferred_lifetime': prefix_opt.preflft,
                    'valid_lifetime': prefix_opt.validlft
                })
                # 다음 IAPrefix 옵션 찾기 (payload 체인에서)
                prefix_opt = prefix_opt.payload.getlayer(DHCP6OptIAPrefix) if prefix_opt.payload else None

        return result

    def build_relay_forward(self, client_message, server_address, relay_address=None, peer_address=None):
        """
        RELAY-FORW 메시지 생성 (클라이언트 메시지를 Relay Agent가 서버로 전달)

        Args:
            client_message: 원본 클라이언트 DHCPv6 메시지 (SOLICIT, REQUEST 등)
            server_address: DHCPv6 서버 IPv6 주소 (유니캐스트)
            relay_address: Relay Agent의 link-local 주소 (기본값: "::")
            peer_address: 클라이언트의 link-local 주소 (기본값: "::")

        Returns:
            scapy 패킷 객체
        """
        # Relay-forward 메시지 생성
        relay_msg = DHCP6_RelayForward(
            hopcount=0,  # 직접 연결된 클라이언트
            linkaddr=relay_address or "::",
            peeraddr=peer_address or "::"
        )

        # 원본 클라이언트 메시지를 Relay Message Option으로 감싸기
        # 클라이언트 메시지에서 DHCPv6 레이어만 추출
        if client_message.haslayer(UDP):
            dhcp6_payload = bytes(client_message[UDP].payload)
        else:
            dhcp6_payload = bytes(client_message)

        relay_msg /= DHCP6OptRelayMsg(message=dhcp6_payload)

        # IPv6 및 UDP 헤더 추가 (서버로 유니캐스트)
        pkt = IPv6(dst=server_address)
        pkt /= UDP(sport=DHCPV6_CLIENT_PORT, dport=DHCPV6_SERVER_PORT)
        pkt /= relay_msg

        return pkt

    @staticmethod
    def parse_relay_reply(pkt):
        """
        RELAY-REPL 메시지 파싱하여 원본 서버 응답 추출

        Args:
            pkt: scapy RELAY-REPL 패킷 객체

        Returns:
            scapy 패킷 객체: 원본 서버 응답 (ADVERTISE, REPLY 등)
        """
        if not pkt.haslayer(DHCP6_RelayReply):
            return None

        # Relay Message Option에서 원본 서버 응답 추출
        if pkt.haslayer(DHCP6OptRelayMsg):
            relay_msg_opt = pkt[DHCP6OptRelayMsg]
            # message 필드에서 DHCPv6 메시지 재구성
            dhcp6_msg = DHCP6(relay_msg_opt.message)
            return dhcp6_msg

        return None
