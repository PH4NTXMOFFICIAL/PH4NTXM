# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import sys

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

from ph4ntxm_opsec_ui import (
    Application,
    ReportWindow,
    add_class,
    data_row,
    finding_row,
    label,
    scroll,
    section,
)
from ph4ntxm_opsec_net.checks import is_local_ip
from ph4ntxm_opsec_net.remediation import lockdown_enabled, toggle_lockdown
from ph4ntxm_opsec_net.report import (
    collect_report,
    connection_status,
    format_finding,
    plain_report,
    verdict,
)


class NetworkWindow(ReportWindow):
    def __init__(self, application):
        super().__init__(
            application,
            "PH4NTXM OpSec Network",
            "Network exposure, connections and resolver evidence",
            "ph4ntxm-opsec-net",
        )

    def build_pages(self):
        self.overview = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.stack.add_titled(scroll(self.overview), "overview", "Overview")

        connections = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        connection_section = section("Active connections")
        self.connection_count = label("Run a check to collect active connections", "subtitle")
        connection_section.pack_start(self.connection_count, False, False, 0)
        self.connection_search = Gtk.SearchEntry()
        self.connection_search.set_placeholder_text("Search endpoints, processes, PIDs or executable paths")
        self.connection_search.connect("search-changed", self.on_search)
        connection_section.pack_start(self.connection_search, False, False, 0)
        self.connection_model = Gtk.ListStore(*([str] * 12), int)
        self.connection_filter = self.connection_model.filter_new()
        self.connection_filter.set_visible_func(self.connection_visible)
        self.connection_sort = Gtk.TreeModelSort(model=self.connection_filter)
        self.connection_table = self.table(
            self.connection_sort,
            [
                ("Status", 0, 140),
                ("Protocol", 1, 80),
                ("State", 2, 100),
                ("Local endpoint", 3, 210),
                ("Remote endpoint", 4, 210),
                ("Process", 5, 140),
                ("PID", 6, 80),
                ("UID", 7, 80),
                ("Executable", 8, 300),
                ("PTR", 9, 230),
                ("Process evidence", 10, 150),
                ("Receive / send queues", 11, 160),
            ],
        )
        self.connection_table.get_selection().connect("changed", self.on_connection_selected)
        table_scroll = scroll(self.connection_table)
        table_scroll.set_min_content_height(300)
        connection_section.pack_start(table_scroll, True, True, 0)
        connections.pack_start(connection_section, True, True, 0)
        details = section("Selected connection")
        self.connection_details = Gtk.TextView()
        self.connection_details.set_editable(False)
        self.connection_details.set_cursor_visible(False)
        self.connection_details.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.connection_details.set_monospace(True)
        self.connection_details.set_left_margin(10)
        self.connection_details.set_right_margin(10)
        detail_scroll = scroll(self.connection_details)
        detail_scroll.set_min_content_height(210)
        details.pack_start(detail_scroll, True, True, 0)
        connections.pack_start(details, False, True, 0)
        self.stack.add_titled(scroll(connections), "connections", "Connections")

        dns_routes = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.dns_evidence = section("DNS configuration")
        dns_routes.pack_start(self.dns_evidence, False, False, 0)
        self.routes_evidence = section("Default routes")
        dns_routes.pack_start(self.routes_evidence, False, False, 0)
        self.stack.add_titled(scroll(dns_routes), "dns-routes", "DNS & routes")

        self.isolation = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.stack.add_titled(scroll(self.isolation), "isolation", "IPv6 & namespace")
        self.current_connections = []
        self.suspicious_connections = []
        self.connection_details.get_buffer().set_text("Select a connection to inspect its complete evidence.")

    def collect_report(self, progress):
        return collect_report(progress)

    def clear_pages(self):
        self.connection_model.clear()
        self.current_connections = []
        self.suspicious_connections = []
        self.connection_count.set_text("Reading active connections…")
        self.connection_details.get_buffer().set_text("Select a connection to inspect its complete evidence.")
        self.clear(self.dns_evidence)
        self.clear(self.routes_evidence)
        self.clear(self.isolation)
        self.action_buttons.clear()

    def populate(self, report):
        self.current_connections = report["connection_data"]["data"].get("connections", [])
        self.suspicious_connections = report["connection_analysis"]["data"].get("suspicious", [])
        assessment = report["assessment"]
        detail = (
            f"{len(self.current_connections)} active connections · "
            f"{len(self.suspicious_connections)} heuristic matches · "
            f"{len(report['dns_data']['data'].get('servers', []))} configured DNS servers"
        )
        if assessment["ok"]:
            score = assessment["data"]["score"]
            title, status = verdict(score)
            self.set_summary(
                title,
                score=score,
                status=status,
                detail=detail,
                updated=report["collected_at"],
            )
        else:
            self.set_summary(
                "Network assessment unavailable",
                status="warn",
                detail=assessment.get("error") or "Required network evidence could not be collected",
                updated=report["collected_at"],
            )

        findings = section("Findings")
        if assessment["ok"]:
            items = assessment["data"].get("findings", [])
            for item in items:
                text, status = format_finding(item)
                findings.pack_start(finding_row(text, status), False, False, 0)
            if not items:
                findings.pack_start(finding_row("No findings detected", "good"), False, False, 0)
        else:
            findings.pack_start(
                finding_row(assessment.get("error") or "Assessment unavailable", "warn"),
                False,
                False,
                0,
            )
        self.overview.pack_start(findings, False, False, 0)

        observed = section("Observed evidence")
        observed.pack_start(data_row("Active connections", str(len(self.current_connections))), False, False, 0)
        observed.pack_start(data_row("Heuristic matches", str(len(self.suspicious_connections))), False, False, 0)
        observed.pack_start(
            data_row("Default routes", str(len(report["route_analysis"]["data"].get("routes", [])))),
            False,
            False,
            0,
        )
        observed.pack_start(label("Heuristic findings describe observed behavior and need review.", "subtitle"), False, False, 0)
        self.overview.pack_start(observed, False, False, 0)

        if report["unavailable"]:
            unavailable = section("Unavailable evidence")
            for message in report["unavailable"]:
                unavailable.pack_start(finding_row(message, "warn", "Unavailable"), False, False, 0)
            self.overview.pack_start(unavailable, False, False, 0)

        lockdown = section("Network Lockdown")
        enabled = report["lockdown_enabled"]
        lockdown.pack_start(
            finding_row("Incoming and outgoing traffic isolation", "good" if enabled else "info", "Enabled" if enabled else "Disabled"),
            False,
            False,
            0,
        )
        action = Gtk.Button(label="Disable Network Lockdown…" if enabled else "Enable Network Lockdown…")
        action.set_halign(Gtk.Align.START)
        add_class(action, "danger" if enabled else "safe")
        action.connect("clicked", self.on_lockdown)
        self.action_buttons.append(action)
        lockdown.pack_start(action, False, False, 0)
        self.overview.pack_start(lockdown, False, False, 0)

        for index, connection in enumerate(self.current_connections):
            matched = connection_status(connection, self.suspicious_connections) == "bad"
            self.connection_model.append(
                [
                    "Heuristic match" if matched else "Observed",
                    connection.get("protocol") or "Unknown",
                    connection.get("state") or "Unknown",
                    connection.get("local") or "Unavailable",
                    connection.get("remote") or "Unavailable",
                    connection.get("process") or "Unavailable",
                    str(connection.get("pid") or "Unavailable"),
                    str(connection["uid"]) if connection.get("uid") is not None else "Unavailable",
                    connection.get("exe") or "Unavailable",
                    connection.get("ptr") or "Not collected",
                    "Incomplete" if connection.get("info_only") else "Available",
                    f"{connection.get('recv_q', 'Unavailable')} / {connection.get('send_q', 'Unavailable')}",
                    index,
                ]
            )
        self.connection_filter.refilter()
        self.update_connection_count(report["connection_data"])
        self.populate_dns_routes(report)
        self.populate_isolation(report)
        self.overview.show_all()
        self.dns_evidence.show_all()
        self.routes_evidence.show_all()
        self.isolation.show_all()

    def populate_dns_routes(self, report):
        self.dns_evidence.pack_start(label("DNS configuration", "section-title"), False, False, 0)
        backend = report["dns_backend"]
        self.dns_evidence.pack_start(
            data_row("Resolver backend", backend["data"].get("backend", "Unavailable")),
            False,
            False,
            0,
        )
        servers = report["dns_data"]["data"].get("servers", [])
        for server in servers:
            local = is_local_ip(server)
            self.dns_evidence.pack_start(
                finding_row(server, "info" if local else "warn", "Local resolver" if local else "External resolver"),
                False,
                False,
                0,
            )
        if not servers:
            text = "No DNS servers configured" if report["dns_data"]["ok"] else "DNS server evidence is unavailable"
            self.dns_evidence.pack_start(finding_row(text, "info" if report["dns_data"]["ok"] else "warn"), False, False, 0)

        self.routes_evidence.pack_start(label("Default routes", "section-title"), False, False, 0)
        routes = report["route_analysis"]["data"].get("routes", [])
        for route in routes:
            route_box = section("IPv6 route" if route["family"] == "ipv6" else "IPv4 route")
            route_box.pack_start(data_row("Interface", route.get("interface") or "Unavailable"), False, False, 0)
            route_box.pack_start(data_row("Gateway", route.get("gateway") or "Direct route"), False, False, 0)
            route_box.pack_start(label(route["raw"], "data-value", True), False, False, 0)
            self.routes_evidence.pack_start(route_box, False, False, 0)
        if not routes:
            missing = report["route_data"]["data"].get("unavailable") or not report["route_analysis"]["ok"]
            text = "Default route evidence is unavailable" if missing else "No default routes detected (offline)"
            self.routes_evidence.pack_start(finding_row(text, "warn" if missing else "info"), False, False, 0)
        for missing in report["route_data"]["data"].get("unavailable", []):
            family = "IPv6" if missing["family"] == "ipv6" else "IPv4"
            text = f"{family}: {missing.get('error') or 'Route evidence unavailable'}"
            self.routes_evidence.pack_start(finding_row(text, "warn", "Unavailable"), False, False, 0)

    def populate_isolation(self, report):
        ipv6_section = section("IPv6 exposure")
        ipv6 = report["ipv6"]
        if ipv6["ok"]:
            enabled = ipv6["data"]["enabled"]
            ipv6_section.pack_start(
                finding_row("IPv6 networking", "warn" if enabled and report.get("mode") == "lonewolf" else "info" if enabled else "good", "Enabled" if enabled else "Disabled"),
                False,
                False,
                0,
            )
            ipv6_section.pack_start(data_row("net.ipv6.conf.all.disable_ipv6", ipv6["data"].get("raw_value", "Unavailable")), False, False, 0)
            ipv6_section.pack_start(label("IPv6 contributes to the existing assessment when Lonewolf mode is active.", "subtitle"), False, False, 0)
        else:
            ipv6_section.pack_start(finding_row(ipv6.get("error") or "IPv6 evidence is unavailable", "warn", "Unavailable"), False, False, 0)
        self.isolation.pack_start(ipv6_section, False, False, 0)

        namespace_section = section("Network namespace")
        namespace = report["namespace"]
        evidence = namespace["data"]
        if namespace["ok"] and evidence.get("available"):
            isolated = evidence["isolated"]
            namespace_section.pack_start(
                finding_row("Namespace isolation", "good" if isolated else "info", "Isolated" if isolated else "Shared"),
                False,
                False,
                0,
            )
            namespace_section.pack_start(data_row("Current process", evidence["namespace"]), False, False, 0)
            namespace_section.pack_start(data_row("Init process", evidence.get("init_namespace") or "Unavailable"), False, False, 0)
            if not isolated:
                namespace_section.pack_start(label("The host network namespace is shared intentionally.", "subtitle"), False, False, 0)
        else:
            namespace_section.pack_start(finding_row("Network namespace visibility is restricted", "info", "Unavailable"), False, False, 0)
        self.isolation.pack_start(namespace_section, False, False, 0)

    def connection_visible(self, model, iterator, data=None):
        query = self.connection_search.get_text().strip().casefold()
        return not query or any(query in str(model[iterator][index]).casefold() for index in range(12))

    def on_search(self, entry):
        self.connection_filter.refilter()
        self.update_connection_count()

    def update_connection_count(self, outcome=None):
        if outcome is not None and not outcome["ok"]:
            self.connection_count.set_text(outcome.get("error") or "Connection evidence is unavailable")
            return
        total = len(self.current_connections)
        shown = len(self.connection_filter)
        self.connection_count.set_text(f"{shown} of {total} active connections shown")

    def on_connection_selected(self, selection):
        model, iterator = selection.get_selected()
        if iterator is None:
            self.connection_details.get_buffer().set_text("Select a connection to inspect its complete evidence.")
            return
        index = model[iterator][12]
        if index >= len(self.current_connections):
            return
        connection = self.current_connections[index]
        names = [
            ("Protocol", "protocol"),
            ("State", "state"),
            ("Local endpoint", "local"),
            ("Remote endpoint", "remote"),
            ("Remote IP", "ip"),
            ("Process", "process"),
            ("PID", "pid"),
            ("UID", "uid"),
            ("Executable", "exe"),
            ("Receive queue", "recv_q"),
            ("Send queue", "send_q"),
        ]
        lines = [f"{name}: {connection.get(key) if connection.get(key) is not None else 'Unavailable'}" for name, key in names]
        lines.append(f"PTR: {connection.get('ptr') or 'Not collected'}")
        lines.append(f"Process evidence: {'Incomplete' if connection.get('info_only') else 'Available'}")
        reasons = []
        for item in self.suspicious_connections:
            if item.get("ip") == connection.get("ip") and item.get("pid") == connection.get("pid"):
                reasons.extend(item.get("reasons", []))
        if reasons:
            lines.extend(["", "Heuristic findings", *(format_finding(item)[0] for item in dict.fromkeys(reasons))])
        lines.extend(["", "Raw connection evidence", connection.get("raw") or "Unavailable"])
        self.connection_details.get_buffer().set_text("\n".join(lines))

    def on_lockdown(self, button):
        enabled = bool(lockdown_enabled())
        title = "Disable Network Lockdown" if enabled else "Enable Network Lockdown"
        consequence = (
            "Disabling lockdown can restore incoming and outgoing network traffic."
            if enabled
            else "Enabling lockdown can block all incoming and outgoing network traffic."
        )
        message = f"The Network Lockdown control will open. {consequence}"
        if not self.confirm_action(title, message, "Open Control"):
            return
        self.run_action(toggle_lockdown, self.on_lockdown_complete, "Waiting for the Network Lockdown control")

    def on_lockdown_complete(self, outcome):
        if outcome["ok"]:
            self.show_message("Network Lockdown", outcome.get("message") or "The lockdown control has closed.")
            self.refresh()
        else:
            self.show_message("Network Lockdown failed", outcome.get("error") or "The lockdown control could not be opened.", error=True)

    def copy_text(self, report):
        return plain_report(report)


def main():
    return Application(NetworkWindow, "org.ph4ntxm.OpSecNetwork").run(sys.argv)


if __name__ == "__main__":
    main()
