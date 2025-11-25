"""실시간 대시보드 UI 모듈"""

import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from dhcpv6_client import DHCPv6Client


class DHCPv6Dashboard:
    """DHCPv6 시뮬레이터 실시간 대시보드"""

    # 상태별 색상 및 아이콘
    STATE_COLORS = {
        DHCPv6Client.STATE_INIT: ("yellow", "⚪"),
        DHCPv6Client.STATE_SELECTING: ("cyan", "🔍"),
        DHCPv6Client.STATE_REQUESTING: ("blue", "📨"),
        DHCPv6Client.STATE_BOUND: ("green", "✅"),
        DHCPv6Client.STATE_RENEWING: ("magenta", "🔄"),
        DHCPv6Client.STATE_REBINDING: ("red", "⚠️"),
    }

    def __init__(self, clients, interface, duration, request_prefix=False):
        """
        대시보드 초기화

        Args:
            clients: DHCPv6Client 객체 리스트
            interface: 네트워크 인터페이스 이름
            duration: 총 실행 시간 (초)
            request_prefix: Prefix Delegation 요청 여부
        """
        self.clients = clients
        self.interface = interface
        self.duration = duration
        self.request_prefix = request_prefix
        self.console = Console()
        self.start_time = time.time()

    def generate_layout(self):
        """대시보드 레이아웃 생성"""
        layout = Layout()

        # 3개 영역으로 분할: 헤더, 메인, 푸터
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=8)
        )

        # 메인 영역을 좌우로 분할
        layout["main"].split_row(
            Layout(name="clients", ratio=3),
            Layout(name="stats", ratio=1)
        )

        # 각 영역 업데이트
        layout["header"].update(self._generate_header())
        layout["clients"].update(self._generate_clients_table())
        layout["stats"].update(self._generate_stats_panel())
        layout["footer"].update(self._generate_footer())

        return layout

    def _generate_header(self):
        """헤더 생성"""
        elapsed = int(time.time() - self.start_time)
        remaining = max(0, self.duration - elapsed)

        header_text = Text()
        header_text.append("DHCPv6 Client Simulator", style="bold cyan")
        header_text.append(" | ", style="dim")
        header_text.append(f"Interface: {self.interface}", style="bold yellow")
        header_text.append(" | ", style="dim")
        header_text.append(f"Running: {elapsed}s / {self.duration}s", style="bold green")
        header_text.append(" | ", style="dim")
        header_text.append(f"Remaining: {remaining}s", style="bold magenta")

        return Panel(header_text, border_style="bright_blue")

    def _generate_clients_table(self):
        """클라이언트 테이블 생성"""
        table = Table(
            title="Client Status",
            show_header=True,
            header_style="bold magenta",
            border_style="blue",
            expand=True
        )

        # 컬럼 추가
        table.add_column("ID", style="cyan", no_wrap=True, width=12)
        table.add_column("State", style="yellow", no_wrap=True, width=15)
        table.add_column("IPv6 Address", style="green", width=25)

        if self.request_prefix:
            table.add_column("Delegated Prefix", style="blue", width=25)

        # 각 클라이언트 정보 추가
        for client in self.clients:
            status = client.get_status()

            # 상태 아이콘 및 색상
            state = status['state']
            color, icon = self.STATE_COLORS.get(state, ("white", "❓"))
            state_text = f"{icon} {state}"

            # 주소 정보
            addresses = status['addresses']
            if addresses:
                addr_text = addresses[0]['address']
                if len(addresses) > 1:
                    addr_text += f" (+{len(addresses)-1})"
            else:
                addr_text = "[dim]-[/dim]"

            # 행 추가
            row_data = [
                status['client_id'],
                f"[{color}]{state_text}[/{color}]",
                addr_text
            ]

            # Prefix Delegation 정보 추가
            if self.request_prefix:
                prefixes = status['prefixes']
                if prefixes:
                    prefix_text = f"{prefixes[0]['prefix']}/{prefixes[0]['prefix_length']}"
                    if len(prefixes) > 1:
                        prefix_text += f" (+{len(prefixes)-1})"
                else:
                    prefix_text = "[dim]-[/dim]"
                row_data.append(prefix_text)

            table.add_row(*row_data)

        return Panel(table, border_style="bright_blue")

    def _generate_stats_panel(self):
        """통계 패널 생성"""
        # 통계 수집
        total = len(self.clients)
        state_counts = {
            DHCPv6Client.STATE_INIT: 0,
            DHCPv6Client.STATE_SELECTING: 0,
            DHCPv6Client.STATE_REQUESTING: 0,
            DHCPv6Client.STATE_BOUND: 0,
            DHCPv6Client.STATE_RENEWING: 0,
            DHCPv6Client.STATE_REBINDING: 0,
        }

        total_addresses = 0
        total_prefixes = 0

        for client in self.clients:
            status = client.get_status()
            state_counts[status['state']] += 1
            total_addresses += len(status['addresses'])
            total_prefixes += len(status['prefixes'])

        # 통계 테이블 생성
        stats_table = Table(show_header=False, box=None, expand=True)
        stats_table.add_column("Label", style="cyan")
        stats_table.add_column("Value", style="yellow", justify="right")

        stats_table.add_row("Total Clients", str(total))
        stats_table.add_row("", "")  # 구분선

        # 각 상태별 카운트
        for state, count in state_counts.items():
            if count > 0:
                color, icon = self.STATE_COLORS.get(state, ("white", ""))
                label = f"{icon} {state}"
                stats_table.add_row(label, f"[{color}]{count}[/{color}]")

        stats_table.add_row("", "")  # 구분선
        stats_table.add_row("Addresses", f"[green]{total_addresses}[/green]")

        if self.request_prefix:
            stats_table.add_row("Prefixes", f"[blue]{total_prefixes}[/blue]")

        # 성공률 계산
        success_rate = (state_counts[DHCPv6Client.STATE_BOUND] / total * 100) if total > 0 else 0
        stats_table.add_row("", "")
        stats_table.add_row(
            "Success Rate",
            f"[{'green' if success_rate >= 80 else 'yellow' if success_rate >= 50 else 'red'}]{success_rate:.1f}%[/]"
        )

        return Panel(stats_table, title="Statistics", border_style="bright_green")

    def _generate_footer(self):
        """푸터 생성 (최근 이벤트 로그)"""
        footer_text = Text()
        footer_text.append("Recent Events:\n", style="bold cyan")

        # 최근 3개 클라이언트의 상태 변화 표시
        recent_events = []
        for client in self.clients[-3:]:  # 최근 3개
            status = client.get_status()
            state = status['state']
            color, icon = self.STATE_COLORS.get(state, ("white", ""))

            event_line = f"{icon} {status['client_id']}: {state}"
            if status['addresses']:
                event_line += f" -> {status['addresses'][0]['address']}"

            footer_text.append(f"  {event_line}\n", style=color)

        footer_text.append("\n", style="dim")
        footer_text.append("Press Ctrl+C to stop", style="dim italic")

        return Panel(footer_text, border_style="bright_yellow")


class DashboardRunner:
    """대시보드 실행 래퍼"""

    def __init__(self, dashboard, update_interval=1.0):
        """
        Args:
            dashboard: DHCPv6Dashboard 객체
            update_interval: 화면 업데이트 간격 (초)
        """
        self.dashboard = dashboard
        self.update_interval = update_interval
        self.running = False

    def start(self):
        """대시보드 시작"""
        self.running = True
        console = Console()

        with Live(
            self.dashboard.generate_layout(),
            console=console,
            screen=False,
            refresh_per_second=1.0 / self.update_interval,
            vertical_overflow="visible"
        ) as live:
            while self.running:
                try:
                    live.update(self.dashboard.generate_layout())
                    time.sleep(self.update_interval)
                except KeyboardInterrupt:
                    break

    def stop(self):
        """대시보드 중지"""
        self.running = False
