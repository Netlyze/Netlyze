import scapy.all as scapy
import socket
import datetime
from plyer import notification
import numpy as np
import time
import pickle
from sklearn.preprocessing import StandardScaler
import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
from dash import dcc, html, Input, Output, State, dash_table
import base64
import io
import os
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl
from threading import Thread
from collections import deque

# Global variables for packet counting
packet_count_history = deque(maxlen=60)  # Store last 60 data points
last_update_time = time.time()
packet_count = 0
packet_times = deque(maxlen=300)



# Log File Paths
DOWNLOADS_DIR = os.path.join(os.path.expanduser("~"), "Downloads")
LOG_FILE = os.path.join(DOWNLOADS_DIR, "network_logs.txt")
ANOMALY_LOG_FILE = os.path.join(DOWNLOADS_DIR, "anomaly_logs.txt")
SUGGESTION_FILE = os.path.join(DOWNLOADS_DIR, "optimization_suggestions.txt")


class DecisionTree:
    def __init__(self, max_depth=3):
        self.max_depth = max_depth
        self.tree = None

    def predict(self, X):
        return np.array([self._predict_input(x, self.tree) for x in X])

    def _predict_input(self, x, tree):
        if not isinstance(tree, tuple):
            return tree
        feature, threshold, left, right = tree
        if x[feature] < threshold:
            return self._predict_input(x, left)
        else:
            return self._predict_input(x, right)


class HybridEnsemble:
    def __init__(self, n_rf=5, n_gb=5, learning_rate=0.1, max_depth=3):
        self.n_rf = n_rf
        self.n_gb = n_gb
        self.learning_rate = learning_rate
        self.max_depth = max_depth
        self.rf_trees = []
        self.gb_trees = []

    def predict(self, X):
        pred = self._rf_predict(X)
        for tree in self.gb_trees:
            pred += self.learning_rate * tree.predict(X)
        return pred

    def _rf_predict(self, X):
        preds = np.array([tree.predict(X) for tree in self.rf_trees])
        return np.mean(preds, axis=0)


def mean_squared_error(y_true, y_pred):
    return np.mean((y_true - y_pred) ** 2)

with open(r"C:\Users\deshp\Downloads\hybrid_ensemble_model.pkl", "rb") as f:
    model = pickle.load(f)
    print("model loaded")


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip


def send_desktop_alert(message):
    notification.notify(
        title="⚠️ Netlyze Alert",
        message=f"{message}\nPlease open Netlyze Dashboard.",
        app_name="Netlyze",
        timeout=10
    )


def log_anomaly(event_type, description, solution="Refer to dashboard or investigate manually."):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} | Type: {event_type} | Description: {description} \n"
    with open(ANOMALY_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)


def process_packet(packet):
    global packet_count, last_update_time
    packet_features = [-0.01722204 ,-0.01352926 , 0.77139113,  1.19407625 , 0.88352902  ,0,1.22837752,0,1.22837752 ,-0.01181283 , 1.22894205,-0.01472477,0,0.52935916,0.7235952,0,0,0.28301802,0, 0.55303698 , 0.27495662,  0.44791747 , 0.30278695,0.27474312 , 0.39697934 , 0.27591806]
    try:
        timestamp = datetime.datetime.now()
        packet_times.append(timestamp)
        packet_count += 1

        # Update history every second
        current_time = time.time()
        if current_time - last_update_time >= 1:  # Every 1 second
            packet_count_history.append(packet_count)
            packet_count = 0
            last_update_time = current_time

        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            packet_size = len(packet)
            website = get_hostname(dst_ip)

            if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSQR):
                queried_domain = packet[scapy.DNSQR].qname.decode("utf-8")
                website = queried_domain

            log_entry = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} | Website: {website} | Source: {src_ip} | Destination: {dst_ip} | Size: {packet_size} bytes\n"

            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(log_entry)
            print(log_entry, end="")

            if model.predict(packet_features) == 1:
                log_anomaly("network attack", "there is an attack on the network")
                send_desktop_alert("We have detected an attack on your network")

    except Exception as e:
        print('')


def start_sniffing():
    try:
        scapy.sniff(prn=process_packet, store=False, filter="ip")
    except KeyboardInterrupt:
        print('')


# Initialize Dash app with a dark theme
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])
server = app.server

# Dummy Log Data
log_data = pd.DataFrame({
    "Timestamp": ["12:00 PM", "12:15 PM", "12:30 PM", "12:45 PM", "1:00 PM"],
    "Event": ["High Bandwidth Usage", "Anomaly Detected", "Security Threat", "Optimization Tip", "Resolved Issue"],
    "Details": ["Device: Router 1", "Unusual traffic spike", "Suspicious packet detected", "Switch to Channel 6",
                "Bandwidth stabilized"]
})

# Custom CSS for enhanced 3D UI styling
custom_style = {
    "card_style": {
        "background": "linear-gradient(145deg, #1c1c1c, #232323)",
        "border": "1px solid #2b2b2b",
        "borderRadius": "20px",
        "boxShadow": "8px 8px 15px #101010, -8px -8px 15px #2e2e2e",
        "padding": "20px",
        "marginBottom": "25px",
        "color": "#ffffff",
        "transition": "0.3s",
    },
    "header_style": {
        "color": "#ffffff",
        "fontWeight": "bold",
        "marginBottom": "15px",
        "textShadow": "2px 2px 4px rgba(0, 0, 0, 0.6)"
    },
    "text_style": {
        "color": "#b0b0b0",
        "fontSize": "15px",
        "textShadow": "1px 1px 2px rgba(0, 0, 0, 0.5)"
    },
    "button_style": {
        "background": "linear-gradient(145deg, #28a745, #1e7e34)",
        "border": "none",
        "borderRadius": "30px",
        "padding": "12px 25px",
        "color": "#ffffff",
        "fontWeight": "bold",
        "boxShadow": "0 4px 8px rgba(40, 167, 69, 0.4)",
        "cursor": "pointer"
    }
}

# App Layout
app.layout = dbc.Container([
    dbc.Row([
        dbc.Col(html.H2("\ud83d\udce1 Netlyze Network Dashboard", className="text-light text-center my-4"), width=12)
    ]),

    dbc.Row([
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H6("Bandwidth Usage", className="card-title", style=custom_style["text_style"]),
                html.H2("76%", className="text-success fw-bold"),
                html.P("+6% from last hour", className="card-text", style=custom_style["text_style"])
            ])
        ], style=custom_style["card_style"]), width=4),

        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H6("Detected Anomalies", className="card-title", style=custom_style["text_style"]),
                html.H2("14", className="text-danger fw-bold"),
                html.P("2 critical, 12 minor", className="card-text", style=custom_style["text_style"])
            ])
        ], style=custom_style["card_style"]), width=4),

        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H6("Network Health", className="card-title", style=custom_style["text_style"]),
                html.H2("Good", className="text-primary fw-bold"),
                html.P("Stable since 2 hours", className="card-text", style=custom_style["text_style"])
            ])
        ], style=custom_style["card_style"]), width=4)
    ], className="mb-4"),

    dbc.Row([
        dbc.Col(dbc.Card([
            dcc.Graph(id="traffic-patterns", config={"displayModeBar": False})
        ], style=custom_style["card_style"]), width=6),
        dbc.Col(dbc.Card([
            dcc.Graph(id="anomalies-chart", config={"displayModeBar": False})
        ], style=custom_style["card_style"]), width=6)
    ], className="mb-4"),

    dbc.Row([
        dbc.Col([
            dcc.Upload(
                id="upload-data",
                children=html.Div(
                    ["\ud83d\udcc1 Drag and Drop or ", html.A("Select CSV File", style={"color": "#28a745"})]),
                style={
                    "width": "100%", "height": "60px", "lineHeight": "60px",
                    "borderWidth": "2px", "borderStyle": "dashed", "borderRadius": "10px",
                    "textAlign": "center", "backgroundColor": "#2b2b2b", "color": "#ffffff",
                    "boxShadow": "inset 0 0 10px #000000"
                },
                multiple=False
            )
        ])
    ], className="mb-4"),

    dbc.Row([
        dbc.Col([
            html.H5("\ud83d\udcdc Event Logs", style=custom_style["header_style"]),
            dash_table.DataTable(
                id="log-table",
                columns=[{"name": col, "id": col} for col in log_data.columns],
                data=log_data.to_dict("records"),
                style_table={"overflowX": "auto", "backgroundColor": "#2b2b2b", "borderRadius": "10px"},
                style_header={
                    "backgroundColor": "#343a40",
                    "color": "white",
                    "fontWeight": "bold",
                    "padding": "10px"
                },
                style_cell={
                    "backgroundColor": "#2b2b2b",
                    "color": "white",
                    "padding": "10px",
                    "border": "1px solid #343a40"
                },
                page_size=5
            )
        ])
    ], className="mb-5"),

    dbc.Row([
        dbc.Col([
            html.H5("\ud83d\udca1 Optimization Tips", style=custom_style["header_style"]),
            html.Div(id="suggestion-box", className="p-3", style={
                "backgroundColor": "#2b2b2b",
                "borderRadius": "15px",
                "color": "#ffffff",
                "boxShadow": "4px 4px 12px #101010, -4px -4px 12px #2e2e2e"
            })
        ], width=12)
    ], className="mb-4"),

    dbc.Row([
        dbc.Col([
            html.H5("\ud83d\udd0d Detailed Analysis", style=custom_style["header_style"]),
            html.Div(id="detailed-analysis", className="p-3", style={
                "backgroundColor": "#2b2b2b",
                "borderRadius": "15px",
                "color": "#ffffff",
                "boxShadow": "4px 4px 12px #101010, -4px -4px 12px #2e2e2e"
            })
        ], width=12)
    ])
], fluid=True, style={"backgroundColor": "#1a1a1a", "padding": "25px", "fontFamily": "Segoe UI, sans-serif"})


@app.callback(
    [Output("traffic-patterns", "figure"),
     Output("anomalies-chart", "figure"),
     Output("log-table", "data"),
     Output("suggestion-box", "children"),
     Output("detailed-analysis", "children")],
    [Input("upload-data", "contents")],
    [State("upload-data", "filename")]
)
def update_dashboard(contents, filename):
    if contents is None:
        df = log_data
    else:
        content_type, content_string = contents.split(",")
        decoded = base64.b64decode(content_string)
        df = pd.read_csv(io.StringIO(decoded.decode("utf-8")))

    time_labels = [f"-{i}s" for i in range(len(packet_count_history) - 1, -1, -1)]

    # If no data yet, initialize with zeros
    if not packet_count_history:
        current_data = [0] * 60
    else:
        current_data = list(packet_count_history)

    times = ["12 AM", "6 AM", "12 PM", "6 PM", "12 AM"]
    traffic_data = [80, 100, 120, 110, 130]
    anomalies_week = [3, 7, 5, 9, 6, 8, 4]

    traffic_fig = px.line(
        x=time_labels,
        y=current_data,
        labels={"x": "Time (seconds ago)", "y": "Packets per second"},
        title="📊 Real-Time Network Traffic",
        template="plotly_dark",
        color_discrete_sequence=["#28a745"]
    )

    # Enhance the traffic graph appearance
    traffic_fig.update_layout(
        plot_bgcolor="#2b2b2b",
        paper_bgcolor="#2b2b2b",
        font_color="#ffffff",
        title_font_color="#ffffff",
        margin=dict(l=40, r=40, t=40, b=40),
        xaxis_title="Time (seconds ago)",
        yaxis_title="Packets per second",
        hovermode="x unified"
    )

    if len(current_data) > 5:
        rolling_avg = pd.Series(current_data).rolling(5).mean().tolist()
        traffic_fig.add_scatter(
            x=time_labels,
            y=rolling_avg,
            name="5s Avg",
            line=dict(color="#ff7f0e", width=2, dash="dot")
        )

        # Rest of your callback remains the same for other outputs
    if contents is None:
        df = log_data
    else:
        content_type, content_string = contents.split(",")
        decoded = base64.b64decode(content_string)
        df = pd.read_csv(io.StringIO(decoded.decode("utf-8")))

    anomalies_fig = px.bar(
        x=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        y=anomalies_week, title="\ud83d\udea8 Weekly Anomalies", labels={"y": "Incidents"},
        template="plotly_dark", color=anomalies_week, color_continuous_scale="reds"
    )
    anomalies_fig.update_layout(
        plot_bgcolor="#2b2b2b",
        paper_bgcolor="#2b2b2b",
        font_color="#ffffff",
        title_font_color="#ffffff",
        margin=dict(l=40, r=40, t=40, b=40)
    )

    tips = html.Ul([
        html.Li("\ud83d\udd0c Disconnect from Wi-Fi immediately (Turn off Wi-Fi or unplug the Ethernet cable)"),
        html.Li("\ud83d\udd01 Restart your router (Unplug it, wait 30 seconds, plug back in)"),
        html.Li("\ud83d\udcf4 Turn off your device\u2019s internet (Airplane mode)"),
        html.Li("\ud83d\udcf2 Use mobile data (temporarily)")
    ])

    ...
    tips = html.Ul([
        html.Li("\ud83d\udd0c Disconnect from Wi-Fi immediately (Turn off Wi-Fi or unplug the Ethernet cable)"),
        html.Li("\ud83d\udd01 Restart your router (Unplug it, wait 30 seconds, plug back in)"),
        html.Li("\ud83d\udcf4 Turn off your device\u2019s internet (Airplane mode)"),
        html.Li("\ud83d\udcf2 Use mobile data (temporarily)")
    ])

    analysis = html.Div([
        html.H4("\u26a0\ufe0f What is a Man-in-the-Middle (MITM) Attack?"),
        html.P("A Man-in-the-Middle attack happens when someone secretly intercepts the communication between your device and the internet."),
        html.P("Think of it like this: you're having a private phone call, but someone is secretly listening in and even changing your words before they reach the other person."),
        html.H5("\U0001F9E0 Why it happens:"),
        html.Ul([
            html.Li("Unsecured public Wi-Fi (cafes, airports)"),
            html.Li("Fake Wi-Fi networks created by attackers"),
            html.Li("Weak router passwords")
        ]),

        html.Br(),
        html.H4("\ud83d\udd13 What is an Active Wiretap Attack?"),
        html.P("An Active Wiretap is like someone tapping your internet 'wires' to watch, record, or even modify what you're doing online — like spying on your browsing, passwords, or private data."),
        html.H5("\U0001F9E0 How it happens:"),
        html.Ul([
            html.Li("Infected devices on your network"),
            html.Li("Outdated router firmware"),
            html.Li("Someone physically near you connecting to your network")
        ]),

        html.Br(),
        html.H4("\ud83d\udea8 What to Do When an Attack is Detected"),
        html.P("These are quick, important steps to stay safe:"),
        html.Ul([
            html.Li("\ud83d\udd0c Disconnect from Wi-Fi immediately (Turn off Wi-Fi or unplug the Ethernet cable)"),
            html.Li("\ud83d\udd01 Restart your router (Unplug it, wait 30 seconds, and plug it back in)"),
            html.Li("\ud83d\udcf4 Turn on Airplane Mode (This stops all network activity instantly)"),
            html.Li("\ud83d\udcf2 Use mobile data temporarily (Safer if you need to do something urgent like banking)")
        ]),

        html.Br(),
        html.H4("\ud83e\uddf0 How to Protect Yourself"),
        html.Ul([
            html.Li("\ud83d\udd12 Change your Wi-Fi password regularly - Kick out unknown users from your network."),
            html.Li("\ud83d\udec1 Never use public Wi-Fi without a VPN - Public Wi-Fi is where most MITM attacks happen."),
            html.Li("\ud83e\uddd1\u200d\ud83d\udcbb Keep your router updated - Log into your router settings and install any firmware updates."),
            html.Li("\ud83d\udeab Don\u2019t connect to unknown networks - If a Wi-Fi name looks strange or unfamiliar — skip it."),
            html.Li("\ud83d\udd10 Use HTTPS websites only - Look for a \ud83d\udd10 lock symbol in the browser to ensure secure browsing.")
        ]),

        html.Br(),
        html.H4("\ud83d\udcc8 Bonus: Improve Network Performance"),
        html.Ul([
            html.Li("\ud83d\udcf6 Place your router centrally in your home - Better range and fewer dead zones."),
            html.Li("\ud83c\udfa9 Reduce connected devices during gaming or streaming - Too many devices slow down the network."),
            html.Li("\ud83d\udec1 Change your Wi-Fi channel - Helps avoid interference from neighbors' routers."),
            html.Li("\ud83d\udd27 Restart router weekly - Clears glitches and refreshes performance.")
        ])
    ])

    return traffic_fig, anomalies_fig, df.to_dict("records"), tips, analysis

class DashApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Netlyze - Network Monitor")
        self.setGeometry(100, 100, 1280, 800)
        self.browser = QWebEngineView()
        self.browser.setUrl(QUrl("http://127.0.0.1:8050/"))
        layout = QVBoxLayout()
        layout.addWidget(self.browser)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)


def run_dash():
    app.run(debug=False, use_reloader=False)


if __name__ == "__main__":
    #Start packet sniffing in a separate thread
    sniff_thread = Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    # Start Dash in a separate thread
    dash_thread = Thread(target=run_dash)
    dash_thread.daemon = True
    dash_thread.start()

    # Start Qt application
    qt_app = QApplication(sys.argv)
    main_window = DashApp()
    main_window.show()
    time.sleep(5)
    send_desktop_alert("New Anomaly found! ")
    sys.exit(qt_app.exec_())

    