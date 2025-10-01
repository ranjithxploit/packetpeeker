import csv
from datetime import datetime
from scapy.all import AsyncSniffer, IP, TCP, Raw, get_if_list
import sys
from PyQt5 import QtWidgets, QtCore, QtGui

CSV_FILE = "log.csv"

with open(CSV_FILE, "w", newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Method", "Payload Snippet"])


class PacketSignal(QtCore.QObject):
    packet_captured = QtCore.pyqtSignal(dict)


class PacketPeekApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("📡 PacketPeek++ (PyQt) — Desktop Sniffer")
        self.resize(1000, 650)
        self.sniffer = None
        self.signals = PacketSignal()
        self.signals.packet_captured.connect(self.display_packet)
        self.init_ui()
        self.is_sniffing = False

    def init_ui(self):
        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()
        controls = QtWidgets.QHBoxLayout()

        iface_label = QtWidgets.QLabel("Interface:")
        self.iface_combo = QtWidgets.QComboBox()
        try:
            interfaces = get_if_list()
        except Exception:
            interfaces = []
        if not interfaces:
            interfaces = ["(no interfaces found)"]
        self.iface_combo.addItems(interfaces)

        self.start_btn = QtWidgets.QPushButton("Start Sniffing")
        self.start_btn.setStyleSheet("background-color: #2ecc71; color: white; font-weight:bold;")
        self.start_btn.clicked.connect(self.start_sniffing)

        self.stop_btn = QtWidgets.QPushButton("Stop Sniffing")
        self.stop_btn.setStyleSheet("background-color: #e74c3c; color: white; font-weight:bold;")
        self.stop_btn.clicked.connect(self.stop_sniffing)
        self.stop_btn.setEnabled(False)

        self.status_label = QtWidgets.QLabel("Status: Stopped")
        self.status_label.setAlignment(QtCore.Qt.AlignCenter)
        self.status_label.setFixedWidth(200)
        self.update_status_style(running=False)

        controls.addWidget(iface_label)
        controls.addWidget(self.iface_combo)
        controls.addStretch()
        controls.addWidget(self.start_btn)
        controls.addWidget(self.stop_btn)
        controls.addWidget(self.status_label)

        self.output = QtWidgets.QTextEdit()
        self.output.setReadOnly(True)
        font = QtGui.QFont("Consolas", 10)
        self.output.setFont(font)

        bottom_controls = QtWidgets.QHBoxLayout()
        self.clear_btn = QtWidgets.QPushButton("Clear Output")
        self.clear_btn.clicked.connect(self.output.clear)
        self.open_csv_btn = QtWidgets.QPushButton("Open CSV Folder")
        self.open_csv_btn.clicked.connect(self.open_csv_location)

        bottom_controls.addWidget(self.clear_btn)
        bottom_controls.addWidget(self.open_csv_btn)
        bottom_controls.addStretch()

        layout.addLayout(controls)
        layout.addWidget(self.output)
        layout.addLayout(bottom_controls)
        central.setLayout(layout)
        self.setCentralWidget(central)

    def update_status_style(self, running: bool):
        if running:
            self.status_label.setText("Status: Running")
            self.status_label.setStyleSheet("background-color: #27ae60; color: white; padding:6px; border-radius:6px;")
        else:
            self.status_label.setText("Status: Stopped")
            self.status_label.setStyleSheet("background-color: #7f8c8d; color: white; padding:6px; border-radius:6px;")

    def start_sniffing(self):
        if self.is_sniffing:
            return
        iface = self.iface_combo.currentText()
        if "(no interfaces" in iface:
            QtWidgets.QMessageBox.warning(self, "No Interface", "No network interface available to sniff.")
            return

        self.output.append(f"Starting sniffing on interface: {iface}\n")
        # Disable start, enable stop
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.is_sniffing = True
        self.update_status_style(running=True)

        self.sniffer = AsyncSniffer(iface=iface, prn=self._on_packet, store=False)
        try:
            self.sniffer.start()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Sniffer Error", f"Failed to start sniffer:\n{e}")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.iface_combo.setEnabled(True)
            self.is_sniffing = False
            self.update_status_style(running=False)

    def stop_sniffing(self):
        if not self.is_sniffing:
            return
        self.output.append("\nStopping sniffing.\n")
        self.stop_btn.setEnabled(False)
        try:
            if self.sniffer:
                self.sniffer.stop()
                self.sniffer = None
        except Exception as e:
            self.output.append(f"Error stopping sniffer: {e}\n")
        self.is_sniffing = False
        self.start_btn.setEnabled(True)
        self.iface_combo.setEnabled(True)
        self.update_status_style(running=False)
        self.output.append("Sniffing stopped.\n")

    def open_csv_location(self):
        import os
        folder = os.path.abspath(".")
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(folder))

    def _on_packet(self, packet):
        try:
            pkt_info = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "src": "",
                        "dst": "",
                        "proto": "",
                        "method": "OTHER",
                        "payload": ""}
            if packet.haslayer(IP):
                pkt_info["src"] = packet[IP].src
                pkt_info["dst"] = packet[IP].dst
            if packet.haslayer(TCP):
                pkt_info["proto"] = "TCP"
                # detect common HTTP ports
                ports = (packet[TCP].sport, packet[TCP].dport)
                if packet.haslayer(Raw):
                    raw = packet[Raw].load.decode(errors="ignore")
                    snippet = raw.replace("\r", " ").replace("\n", " ")
                    pkt_info["payload"] = snippet[:200]
                    if "GET " in raw.splitlines()[0] if raw else False:
                        pkt_info["method"] = "GET"
                    elif "POST " in raw.splitlines()[0] if raw else False:
                        pkt_info["method"] = "POST"
                    elif "HTTP/" in raw:
                        pkt_info["method"] = "HTTP"
                else:
                    pkt_info["payload"] = ""
                    pkt_info["method"] = "OTHER"

                if pkt_info["method"] == "OTHER" and (80 in ports or 8080 in ports):
                    pkt_info["method"] = "HTTP"

            else:
                pkt_info["proto"] = packet.__class__.__name__

            try:
                with open(CSV_FILE, "a", newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([pkt_info["timestamp"], pkt_info["src"], pkt_info["dst"],
                                     pkt_info["proto"], pkt_info["method"], pkt_info["payload"]])
            except Exception as e:
                print("CSV write error:", e)

            self.signals.packet_captured.emit(pkt_info)
        except Exception as e:
            print("Packet processing error:", e)

    def display_packet(self, pkt_info):
        ts = pkt_info["timestamp"]
        src = pkt_info["src"]
        dst = pkt_info["dst"]
        proto = pkt_info["proto"]
        method = pkt_info["method"]
        payload = (pkt_info["payload"][:300] + "...") if len(pkt_info["payload"]) > 300 else pkt_info["payload"]

        header = f"[{ts}] {src} -> {dst} | {proto} | {method}\n"
        body = f"Payload: {payload}\n\n"

        color = None
        if method == "GET":
            color = "#2ecc71"
        elif method == "POST":
            color = "#e74c3c"
        elif method in ("HTTP",):
            color = "#3498db"

        if color:
            html = f'<span style="color:{color}; font-family: Consolas;">{header}</span>' \
                   f'<span style="color: #222; font-family: Consolas;">{body}</span>'
        else:
            html = f'<span style="color:#000; font-family: Consolas;">{header}{body}</span>'

        self.output.moveCursor(QtGui.QTextCursor.End)
        self.output.insertHtml(html)
        self.output.moveCursor(QtGui.QTextCursor.End)


def main():
    app = QtWidgets.QApplication(sys.argv)
    w = PacketPeekApp()
    w.show()
    def on_exit():
        if w.is_sniffing and w.sniffer:
            try:
                w.sniffer.stop()
            except Exception:
                pass
    app.aboutToQuit.connect(on_exit)
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
