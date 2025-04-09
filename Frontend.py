import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
from dash import dcc, html, Input, Output, State, dash_table
import base64
import io
import sys
import requests
from bs4 import BeautifulSoup
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl
from threading import Thread

# Initialize Dash app with dark theme
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])
server = app.server

# Default Data for Logs
log_data = pd.DataFrame({
    "Timestamp": ["12:00 PM", "12:15 PM", "12:30 PM", "12:45 PM", "1:00 PM"],
    "Event": ["High Bandwidth Usage", "Anomaly Detected", "Security Threat", "Optimization Tip", "Resolved Issue"],
    "Details": ["Device: Router 1", "Unusual traffic spike", "Suspicious packet detected", "Switch to Channel 6", "Bandwidth stabilized"]
})

# Function to Search for Network Issues
def search(query):
    search_url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(search_url, headers=headers)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        results = soup.find_all("h3")[:3]  
        return "\n".join([res.get_text() for res in results])
    else:
        return "Unable to fetch results."

# Layout
app.layout = dbc.Container(
    [
        dbc.Row(dbc.Col(html.H2("🌐 Network Monitoring Dashboard", className="text-info text-center mt-3"))),

        dbc.Row([
            dbc.Col(dbc.Card(dbc.CardBody([
                html.H4("📊 Bandwidth Usage", className="text-light"),
                html.H2("75%", className="text-success"),
                html.Small("+5%", className="text-muted")
            ])), width=4),

            dbc.Col(dbc.Card(dbc.CardBody([
                html.H4("⚠️ Detected Anomalies", className="text-light"),
                html.H2("12", className="text-danger"),
                html.Small("-2", className="text-muted")
            ])), width=4),

            dbc.Col(dbc.Card(dbc.CardBody([
                html.H4("✅ Network Health", className="text-light"),
                html.H2("Good", className="text-success"),
                html.Small("Stable", className="text-muted")
            ])), width=4),
        ], className="mb-4"),

        dbc.Row([
            dbc.Col(dcc.Graph(id="traffic-patterns"), width=6),
            dbc.Col(dcc.Graph(id="anomalies-chart"), width=6),
        ], className="mb-4"),

        dbc.Row([
            dbc.Col(dcc.Upload(id="upload-data", children=html.Button("📂 Upload CSV", className="btn btn-primary"), multiple=False)),
        ], className="mb-3"),

        html.H4("📜 Logs", className="text-light"),
        dash_table.DataTable(
            id="log-table",
            columns=[{"name": col, "id": col} for col in log_data.columns],
            data=log_data.to_dict("records"),
            style_table={"overflowX": "auto"},
            style_header={"backgroundColor": "#343a40", "color": "white"},
            style_cell={"backgroundColor": "#212529", "color": "white"},
        ),

        html.H4("💡 Network Optimization Tips", className="text-light mt-4"),
        html.Div(id="suggestion-box", className="alert alert-info"),

        html.H4("🔍 Detailed Analysis", className="text-light mt-4"),
        html.Div(id="detailed-analysis", className="alert alert-warning"),
    ],
    fluid=True,
)

@app.callback(
    [Output("traffic-patterns", "figure"), Output("anomalies-chart", "figure"), Output("log-table", "data"), Output("suggestion-box", "children"), Output("detailed-analysis", "children")],
    [Input("upload-data", "contents")],
    [State("upload-data", "filename")]
)
def update_dashboard(contents, filename):
    if contents is None:
        data = log_data
    else:
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)
        data = pd.read_csv(io.StringIO(decoded.decode('utf-8')))

    times = ["12 AM", "6 AM", "12 PM", "6 PM", "12 AM"]
    traffic_data = [80, 90, 110, 120, 130]
    anomalies_week = [4, 8, 6, 10, 12, 7, 9]

    traffic_fig = px.line_3d(x=times, y=[0, 1, 2, 3, 4], z=traffic_data, title="🌐 3D Traffic Patterns", labels={"x": "Time", "z": "Traffic (Mbps)"}, template="plotly_dark")
    anomalies_fig = px.bar(x=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], y=anomalies_week, title="📊 Anomalies Detected", labels={"y": "Incidents"}, template="plotly_dark")

    suggestions = "🚀 Try pausing heavy streaming services. 🔄 Restart your router for better stability."
    search_results = search("How to fix network congestion")
    detailed_analysis = f"🌍 {search_results}"

    return traffic_fig, anomalies_fig, data.to_dict("records"), suggestions, detailed_analysis

# PyQt5 GUI to Run Dash App
class DashApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Dashboard 📡")
        self.setGeometry(100, 100, 1200, 800)
        self.browser = QWebEngineView()
        self.browser.setUrl(QUrl("http://127.0.0.1:8050/"))
        central_widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(self.browser)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

# Run Dash in Background
def run_dash():
    app.run(debug=False, use_reloader=False)

if __name__ == "__main__":
    dash_thread = Thread(target=run_dash)
    dash_thread.start()
    qt_app = QApplication(sys.argv)
    main_window = DashApp()
    main_window.show()
    sys.exit(qt_app.exec_())
    