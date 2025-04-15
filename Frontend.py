import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
from dash import dcc, html, Input, Output, State, dash_table
import base64
import io
import os
import sys
import requests
from bs4 import BeautifulSoup
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl
from threading import Thread

# Initialize Dash app with a dark theme
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])
server = app.server

# Dummy Log Data
log_data = pd.DataFrame({
    "Timestamp": ["12:00 PM", "12:15 PM", "12:30 PM", "12:45 PM", "1:00 PM"],
    "Event": ["High Bandwidth Usage", "Anomaly Detected", "Security Threat", "Optimization Tip", "Resolved Issue"],
    "Details": ["Device: Router 1", "Unusual traffic spike", "Suspicious packet detected", "Switch to Channel 6", "Bandwidth stabilized"]
})

# Google Search Function for Detailed Analysis
def search(query):
    url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
    headers = {"User-Agent": "Mozilla/5.0"}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        soup = BeautifulSoup(r.text, "html.parser")
        return "\n".join([res.get_text() for res in soup.find_all("h3")[:3]])
    else:
        return "No results found."

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
                children=html.Div(["\ud83d\udcc1 Drag and Drop or ", html.A("Select CSV File", style={"color": "#28a745"})]),
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

    times = ["12 AM", "6 AM", "12 PM", "6 PM", "12 AM"]
    traffic_data = [80, 100, 120, 110, 130]
    anomalies_week = [3, 7, 5, 9, 6, 8, 4]

    traffic_fig = px.area(
        x=times, y=traffic_data, labels={"x": "Time", "y": "Bandwidth (Mbps)"},
        title="\ud83d\udcc8 Traffic Flow", template="plotly_dark",
        color_discrete_sequence=["#28a745"]
    )
    traffic_fig.update_layout(
        plot_bgcolor="#2b2b2b",
        paper_bgcolor="#2b2b2b",
        font_color="#ffffff",
        title_font_color="#ffffff",
        margin=dict(l=40, r=40, t=40, b=40)
    )

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

    # Read suggestions from backend
    suggestions_path = os.path.join(os.path.expanduser("~"), "Downloads", "optimization_suggestions.txt")
    if os.path.exists(suggestions_path):
        with open(suggestions_path, "r", encoding="utf-8") as f:
            tips = f.read()
    else:
        tips = "\u2705 All systems operational. No optimizations required yet."

    analysis = f"\U0001F9E0 Insights:\n{search('How to improve home network performance')}"

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
    dash_thread = Thread(target=run_dash)
    dash_thread.start()
    qt_app = QApplication(sys.argv)
    main_window = DashApp()
    main_window.show()
    sys.exit(qt_app.exec_())
    
