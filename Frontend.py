import dash
import dash_bootstrap_components as dbc
import dash.html as html
import dash.dcc as dcc  # Use this import for Dash 2.x and higher
import pandas as pd
import plotly.express as px
import base64
import io
import sys
import requests
from bs4 import BeautifulSoup
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QMessageBox
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl, QTimer
from threading import Thread
import random

# Sample Log Data
log_data = pd.DataFrame({
    "Timestamp": ["12:00 PM", "12:15 PM", "12:30 PM", "12:45 PM", "1:00 PM"],
    "Event": ["High Bandwidth Usage", "Anomaly Detected", "Security Threat", "Optimization Tip", "Resolved Issue"],
    "Details": ["Device: Router 1", "Unusual traffic spike", "Suspicious packet detected", "Switch to Channel 6", "Bandwidth stabilized"]
})

# Dash App Init
dashboard_app = dash.Dash(__name__, external_stylesheets=[dbc.themes.SLATE])
server = dashboard_app.server

# Function: Fetch Suggestions from Google
def search(query):
    try:
        response = requests.get(f"https://www.google.com/search?q={query.replace(' ', '+')}", headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")
        results = soup.find_all("h3")[:3]
        return "\n".join([res.get_text() for res in results])
    except:
        return "Unable to fetch analysis at this time."

# Layout
dashboard_app.layout = dbc.Container([
    dbc.Row(dbc.Col(html.H2("🧠 Network Insights Dashboard", className="text-center text-info my-4 fw-bold", style={"fontSize": "2.8rem"}))),
    
    dbc.Row([
        dbc.Col(dbc.Card(dbc.CardBody([
            html.H4("📈 Bandwidth", className="text-light"),
            html.H2("72%", className="text-success fw-bold"),
            html.Small("+4% from avg", className="text-muted"),
        ]), color="dark", style={"borderRadius": "15px", "background": "#1F4068"}), width=4),

        dbc.Col(dbc.Card(dbc.CardBody([
            html.H4("🚨 Anomalies", className="text-light"),
            html.H2("5", className="text-danger fw-bold"),
            html.Small("Today", className="text-muted"),
        ]), color="dark", style={"borderRadius": "15px", "background": "#8A2387"}), width=4),

        dbc.Col(dbc.Card(dbc.CardBody([
            html.H4("📶 Network Health", className="text-light"),
            html.H2("Good", className="text-primary fw-bold"),
            html.Small("Stable connection", className="text-muted"),
        ]), color="dark", style={"borderRadius": "15px", "background": "#38ef7d"}), width=4),
    ], className="mb-4"),

    dbc.Row([
        dbc.Col(dcc.Graph(id="traffic-patterns"), width=6),
        dbc.Col(dcc.Graph(id="anomalies-chart"), width=6),
    ], className="mb-4"),

    dbc.Row([
        dbc.Col(dcc.Graph(id="protocol-pie"), width=12),
    ], className="mb-4"),

    dbc.Row([
        dbc.Col(dcc.Upload(id="upload-data", children=html.Button("📂 Upload CSV", className="btn btn-outline-info btn-block"), multiple=False), width=12)
    ], className="mb-4 text-center"),

    html.H5("🧾 Event Logs", className="text-warning mb-2"),
    dash.dash_table.DataTable(
        id="log-table",
        columns=[{"name": col, "id": col} for col in log_data.columns],
        data=log_data.to_dict("records"),
        style_table={"overflowX": "auto"},
        style_header={"backgroundColor": "#34495e", "color": "white", "fontWeight": "bold"},
        style_cell={"backgroundColor": "#2c3e50", "color": "white", "textAlign": "center"},
    ),

    html.H5("💡 Suggestions", className="text-info mt-4"),
    html.Div(id="suggestion-box", className="alert alert-primary shadow-sm", style={"fontSize": "1.1rem"}),

    html.H5("🔍 Detailed Analysis", className="text-light mt-4"),
    html.Div(id="detailed-analysis", className="alert alert-warning shadow-sm", style={"fontSize": "1.1rem"}),

], fluid=True, style={"backgroundColor": "#121212", "padding": "20px", "fontFamily": "Segoe UI"})


# Callback
@dashboard_app.callback(
    [dash.Output("traffic-patterns", "figure"),
     dash.Output("anomalies-chart", "figure"),
     dash.Output("protocol-pie", "figure"),
     dash.Output("log-table", "data"),
     dash.Output("suggestion-box", "children"),
     dash.Output("detailed-analysis", "children")],
    [dash.Input("upload-data", "contents")],
    [dash.State("upload-data", "filename")]
)
def update_dashboard(contents, filename):
    if contents:
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)
        df = pd.read_csv(io.StringIO(decoded.decode('utf-8')))
    else:
        df = log_data

    times = ["12 AM", "6 AM", "12 PM", "6 PM", "12 AM"]
    traffic_data = [60, 75, 100, 120, 90]
    anomalies_week = [3, 5, 7, 2, 6, 8, 4]
    protocol_counts = {'TCP': 45, 'UDP': 30, 'ICMP': 15, 'Others': 10}

    fig1 = px.line(x=times, y=traffic_data, title="📶 Traffic Over Time", template="plotly_dark", labels={"x": "Time", "y": "Mbps"})
    fig2 = px.bar(x=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], y=anomalies_week, title="📊 Weekly Anomalies", template="plotly_dark")
    pie_chart = px.pie(names=list(protocol_counts.keys()), values=list(protocol_counts.values()), title="📡 Protocol Distribution", template="plotly_dark", hole=0.4)

    suggestion = "🔌 Disconnect unused devices. 🚀 Switch to 5GHz if possible."
    analysis = search("network traffic anomaly detection")

    return fig1, fig2, pie_chart, df.to_dict("records"), suggestion, analysis

# PyQt5 GUI
class DashApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🧠 Network Dashboard")
        self.setGeometry(100, 100, 1280, 800)

        self.browser = QWebEngineView()
        self.browser.setUrl(QUrl("http://127.0.0.1:8050/"))

        central_widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(self.browser)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Timer for pop-up
        self.timer = QTimer()
        self.timer.timeout.connect(self.show_popup)
        self.timer.start(15000)  # every 15s

    def show_popup(self):
        if random.choice([True, False]):  # Simulate an anomaly trigger
            QMessageBox.warning(self, "⚠️ Anomaly Detected", "Unusual network behavior observed!", QMessageBox.Ok)

# Start Dash Server
def run_dash():
    dashboard_app.run(debug=False, use_reloader=False)

# Entry
if __name__ == "__main__":
    dash_thread = Thread(target=run_dash)
    dash_thread.start()
    qt_app = QApplication(sys.argv)
    main_window = DashApp()
    main_window.show()
    sys.exit(qt_app.exec())
    
