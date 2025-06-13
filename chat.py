import sys
import socket
import threading
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QPushButton, QListWidget, QListWidgetItem, QLabel, QScrollArea, QFrame
)
from PySide6.QtCore import Qt, QSize, Signal, QObject
from PySide6.QtGui import QColor, QPainter, QBrush, QFont

SERVER_HOST = "10.0.1.40"
SERVER_PORT = 8080

class SignalBus(QObject):
    message_received = Signal(str, bool)
    status_updated = Signal(str)

class BubbleWidget(QFrame):
    def __init__(self, text, is_me):
        super().__init__()
        self.text = text
        self.is_me = is_me
        self.setMinimumHeight(40)
        self.setStyleSheet("""
            QFrame {
                border-radius: 18px;
                font-size: 16px;
                padding: 8px 16px;
                max-width: 60%;
            }
        """)

    def paintEvent(self, event):
        painter = QPainter(self)
        color = QColor(0, 135, 95) if self.is_me else QColor(56, 141, 232)
        if not self.is_me:
            color = QColor(230, 230, 235)
        painter.setBrush(QBrush(color))
        painter.setPen(Qt.NoPen)
        rect = self.rect().adjusted(0, 0, -1, -1)
        painter.drawRoundedRect(rect, 18, 18)
        painter.setFont(QFont("Arial", 12))
        painter.setPen(QColor(255, 255, 255) if self.is_me else QColor(20, 20, 25))
        painter.drawText(rect.adjusted(12, 8, -12, -8), Qt.TextWordWrap, self.text)

    def sizeHint(self):
        fm = QFont("Arial", 12)
        font = QFont(fm)
        metrics = self.fontMetrics()
        w = metrics.boundingRect(self.text).width() + 36
        h = metrics.boundingRect(self.text).height() + 28
        return QSize(min(w, 400), max(h, 40))

class ChatWindow(QWidget):
    def __init__(self, host, port):
        super().__init__()
        self.setWindowTitle("Highly Private Chat")
        self.setMinimumSize(500, 700)
        self.signal_bus = SignalBus()

        # GUI
        self.layout = QVBoxLayout(self)
        self.status_label = QLabel("Connecting...")
        self.status_label.setStyleSheet("font-size: 12pt; color: #999;")
        self.layout.addWidget(self.status_label)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.addStretch(1)
        self.scroll.setWidget(self.scroll_content)
        self.layout.addWidget(self.scroll, 1)

        input_layout = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText("Type your message...")
        self.input.setStyleSheet("font-size: 14pt; padding: 8px;")
        self.send_btn = QPushButton("Send")
        self.send_btn.setStyleSheet("background-color: #388ded; color: #fff; font-weight: bold; padding: 8px 16px; border-radius: 8px;")
        self.send_btn.clicked.connect(self.send_message)
        input_layout.addWidget(self.input, 1)
        input_layout.addWidget(self.send_btn)
        self.layout.addLayout(input_layout)

        # Chat state
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False
        self.signal_bus.message_received.connect(self.add_message)
        self.signal_bus.status_updated.connect(self.status_label.setText)

        # Networking
        threading.Thread(target=self.connect_and_listen, args=(host, port), daemon=True).start()

    def connect_and_listen(self, host, port):
        try:
            self.s.connect((host, port))
            self.connected = True
            self.signal_bus.status_updated.emit("Connected. Waiting for chat peer...")
            while True:
                data = self.s.recv(4096)
                if not data:
                    break
                msg = data.decode('utf-8')
                if "Initializing chat" in msg or "Waiting for peer" in msg or "Peer connected!" in msg:
                    self.signal_bus.status_updated.emit(msg.strip())
                else:
                    self.signal_bus.message_received.emit(msg, False)
        except Exception as e:
            self.signal_bus.status_updated.emit(f"Connection failed: {e}")

    def send_message(self):
        msg = self.input.text().strip()
        if msg and self.connected:
            try:
                self.s.sendall(msg.encode('utf-8'))
                self.signal_bus.message_received.emit(msg, True)
            except Exception as e:
                self.status_label.setText(f"Send failed: {e}")
            self.input.clear()

    def add_message(self, msg, is_me):
        bubble = BubbleWidget(msg, is_me)
        hlayout = QHBoxLayout()
        if is_me:
            hlayout.addStretch(1)
            hlayout.addWidget(bubble, 0)
        else:
            hlayout.addWidget(bubble, 0)
            hlayout.addStretch(1)
        self.scroll_layout.insertLayout(self.scroll_layout.count()-1, hlayout)
        self.scroll.verticalScrollBar().setValue(self.scroll.verticalScrollBar().maximum())

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ChatWindow(SERVER_HOST, SERVER_PORT)
    win.show()
    sys.exit(app.exec())
