import os
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyArrowPatch, Circle


OUT_DIR = os.path.join("screenshots", "report_figures")
os.makedirs(OUT_DIR, exist_ok=True)


def save_fig(name: str):
    path = os.path.join(OUT_DIR, name)
    plt.tight_layout()
    plt.savefig(path, dpi=220, bbox_inches="tight")
    plt.close()


def draw_box(ax, x, y, w, h, text, fc="#f5f7fb", ec="#2c3e50", fs=10):
    rect = Rectangle((x, y), w, h, facecolor=fc, edgecolor=ec, linewidth=1.5)
    ax.add_patch(rect)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs)


def draw_arrow(ax, x1, y1, x2, y2, color="#34495e"):
    arr = FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="->", mutation_scale=12, linewidth=1.4, color=color)
    ax.add_patch(arr)


def fig_4_1_architecture():
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.set_xlim(0, 18)
    ax.set_ylim(0, 10)
    ax.axis("off")

    draw_box(ax, 0.8, 4.2, 2.2, 1.2, "Internet\nTraffic", fc="#e8f6ff")
    draw_box(ax, 3.8, 4.2, 2.8, 1.2, "Nginx Edge\nRate + Conn Limit", fc="#fff3e8")
    draw_box(ax, 7.6, 4.2, 2.8, 1.2, "Flask Middleware\nPre-Request Controls", fc="#eafbea")
    draw_box(ax, 11.4, 5.7, 2.8, 1.2, "DDoS Detector\nIP + Distributed", fc="#f2ecff")
    draw_box(ax, 11.4, 2.7, 2.8, 1.2, "Traffic Analyzer\nRisk Scoring", fc="#f2ecff")
    draw_box(ax, 15.0, 5.7, 2.2, 1.2, "Notifier\nWebhook", fc="#fff9d9")
    draw_box(ax, 15.0, 2.7, 2.2, 1.2, "Health Monitor\nCircuit Breaker", fc="#fff9d9")
    draw_box(ax, 11.4, 0.8, 5.8, 1.2, "Protected Response + Security Headers", fc="#e8f6ff")

    draw_arrow(ax, 3.0, 4.8, 3.8, 4.8)
    draw_arrow(ax, 6.6, 4.8, 7.6, 4.8)
    draw_arrow(ax, 10.4, 4.8, 11.4, 6.3)
    draw_arrow(ax, 10.4, 4.8, 11.4, 3.3)
    draw_arrow(ax, 14.2, 6.3, 15.0, 6.3)
    draw_arrow(ax, 14.2, 3.3, 15.0, 3.3)
    draw_arrow(ax, 12.8, 2.7, 12.8, 2.0)
    draw_arrow(ax, 16.1, 2.7, 16.1, 2.0)

    ax.text(9.0, 9.3, "Figure 4.1: Overall Multi-Layer Architecture", fontsize=14, fontweight="bold", ha="center")
    save_fig("Figure_4_1_architecture.png")


def fig_4_2_data_flow():
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.set_xlim(0, 18)
    ax.set_ylim(0, 10)
    ax.axis("off")

    components = [
        (1.0, 7.3, "Client Request"),
        (4.0, 7.3, "Nginx Ingress"),
        (7.2, 7.3, "before_request"),
        (10.4, 7.3, "Rate Limiter"),
        (13.6, 7.3, "Route Handler"),
        (7.2, 4.5, "after_request"),
        (10.4, 4.5, "DDoS Detector"),
        (13.6, 4.5, "Traffic Analyzer"),
        (10.4, 1.7, "Health Monitor"),
        (13.6, 1.7, "Notifier + Dashboard"),
    ]

    for x, y, label in components:
        draw_box(ax, x, y, 2.3, 1.1, label)

    draw_arrow(ax, 3.3, 7.85, 4.0, 7.85)
    draw_arrow(ax, 6.3, 7.85, 7.2, 7.85)
    draw_arrow(ax, 9.5, 7.85, 10.4, 7.85)
    draw_arrow(ax, 12.7, 7.85, 13.6, 7.85)
    draw_arrow(ax, 14.75, 7.3, 14.75, 5.6)
    draw_arrow(ax, 13.6, 5.05, 12.7, 5.05)
    draw_arrow(ax, 10.4, 5.05, 9.5, 5.05)
    draw_arrow(ax, 11.55, 4.5, 11.55, 2.8)
    draw_arrow(ax, 12.7, 2.25, 13.6, 2.25)

    ax.text(9.0, 9.3, "Figure 4.2: Data Flow Across Core Components", fontsize=14, fontweight="bold", ha="center")
    save_fig("Figure_4_2_data_flow.png")


def fig_4_3_state_diagram():
    fig, ax = plt.subplots(figsize=(12, 7))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 8)
    ax.axis("off")

    states = {
        "HEALTHY": (2, 4),
        "DEGRADED": (5, 6),
        "CRITICAL": (8.5, 4),
        "RECOVERING": (5, 2),
    }

    for name, (x, y) in states.items():
        c = Circle((x, y), 1.1, edgecolor="#2c3e50", facecolor="#ecf0f1", linewidth=1.8)
        ax.add_patch(c)
        ax.text(x, y, name, ha="center", va="center", fontsize=10, fontweight="bold")

    draw_arrow(ax, 3.1, 4.7, 4.0, 5.4)
    ax.text(3.4, 5.7, "Minor failures", fontsize=9)

    draw_arrow(ax, 6.1, 5.4, 7.4, 4.7)
    ax.text(6.2, 5.8, "Threshold exceeded", fontsize=9)

    draw_arrow(ax, 7.4, 3.3, 6.1, 2.6)
    ax.text(6.0, 2.9, "Recovery trigger", fontsize=9)

    draw_arrow(ax, 4.0, 2.6, 3.1, 3.3)
    ax.text(2.6, 2.7, "Stable success", fontsize=9)

    draw_arrow(ax, 5.0, 4.9, 5.0, 5.0)

    ax.text(6.0, 7.2, "Figure 4.3: Operational State Transitions in Recovery Subsystem", fontsize=13, fontweight="bold", ha="center")
    save_fig("Figure_4_3_state_diagram.png")


def fig_4_4_use_case():
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 10)
    ax.axis("off")

    # System boundary
    boundary = Rectangle((4.5, 1.5), 9.8, 7.2, edgecolor="#2c3e50", facecolor="#fdfefe", linewidth=1.8)
    ax.add_patch(boundary)
    ax.text(9.4, 8.9, "DDoS Protection Framework", ha="center", fontsize=11, fontweight="bold")

    # Actors
    ax.text(1.2, 5.3, "User", ha="center", fontsize=12)
    ax.text(15.0, 5.3, "Admin", ha="center", fontsize=12)

    use_cases = [
        (9.3, 8.0, "Send HTTP Request"),
        (9.3, 6.8, "View Response"),
        (9.3, 5.6, "Monitor Dashboard"),
        (9.3, 4.4, "Configure Settings"),
        (9.3, 3.2, "Manage IP Blacklist"),
        (9.3, 2.0, "View Attack Logs"),
    ]

    for x, y, t in use_cases:
        c = Circle((x, y), 1.1, edgecolor="#34495e", facecolor="#ecf6ff", linewidth=1.4)
        ax.add_patch(c)
        ax.text(x, y, t, ha="center", va="center", fontsize=8.8)

    # User links
    draw_arrow(ax, 2.2, 5.4, 8.2, 8.0)
    draw_arrow(ax, 2.2, 5.2, 8.2, 6.8)

    # Admin links
    draw_arrow(ax, 14.0, 5.4, 10.4, 8.0)
    draw_arrow(ax, 14.0, 5.2, 10.4, 6.8)
    draw_arrow(ax, 14.0, 5.0, 10.4, 5.6)
    draw_arrow(ax, 14.0, 4.8, 10.4, 4.4)
    draw_arrow(ax, 14.0, 4.6, 10.4, 3.2)
    draw_arrow(ax, 14.0, 4.4, 10.4, 2.0)

    ax.text(8.0, 9.5, "Figure 4.4: Use-Case Interactions for User and Admin", fontsize=13, fontweight="bold", ha="center")
    save_fig("Figure_4_4_use_case.png")


def fig_4_5_sequence():
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 12)
    ax.axis("off")

    actors = ["Client", "Nginx", "Flask\nMiddleware", "Detector", "Limiter", "Health\nMonitor"]
    xs = [1.5, 4.0, 6.8, 9.4, 12.0, 14.3]

    for x, a in zip(xs, actors):
        draw_box(ax, x - 0.8, 10.9, 1.6, 0.8, a, fc="#f7f9fb")
        ax.plot([x, x], [1.0, 10.9], linestyle="--", linewidth=1.1, color="#7f8c8d")

    steps = [
        (1.5, 4.0, 9.8, "HTTP request"),
        (4.0, 6.8, 8.8, "Forward + headers"),
        (6.8, 12.0, 7.8, "check_rate_limit()"),
        (6.8, 9.4, 6.8, "analyze_traffic()"),
        (9.4, 14.3, 5.8, "report_failure/success"),
        (6.8, 1.5, 4.8, "HTTP response (200/429/403)"),
    ]

    for x1, x2, y, label in steps:
        draw_arrow(ax, x1, y, x2, y)
        ax.text((x1 + x2) / 2, y + 0.2, label, ha="center", fontsize=8.8)

    ax.text(8.0, 11.8, "Figure 4.5: Request Lifecycle Sequence", fontsize=13, fontweight="bold", ha="center")
    save_fig("Figure_4_5_sequence.png")


def fig_5_1_simulation_topology():
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.set_xlim(0, 18)
    ax.set_ylim(0, 10)
    ax.axis("off")

    draw_box(ax, 1.0, 6.7, 3.0, 1.3, "Attack Simulator\n(Thread Pool + RPS)", fc="#ffecec")
    draw_box(ax, 5.2, 6.7, 2.8, 1.3, "Docker Network", fc="#eef6ff")
    draw_box(ax, 9.0, 6.7, 2.8, 1.3, "Nginx Service", fc="#fff3e8")
    draw_box(ax, 12.8, 6.7, 3.0, 1.3, "Flask + Gunicorn", fc="#eafbea")

    draw_box(ax, 5.2, 3.8, 3.0, 1.3, "Metrics API\n/admin/stats", fc="#f2ecff")
    draw_box(ax, 9.0, 3.8, 2.8, 1.3, "Attack Logs\n/admin/attacks", fc="#f2ecff")
    draw_box(ax, 12.8, 3.8, 3.0, 1.3, "Dashboard\n/admin/dashboard", fc="#f2ecff")

    draw_arrow(ax, 4.0, 7.35, 5.2, 7.35)
    draw_arrow(ax, 8.0, 7.35, 9.0, 7.35)
    draw_arrow(ax, 11.8, 7.35, 12.8, 7.35)

    draw_arrow(ax, 14.3, 6.7, 14.3, 5.1)
    draw_arrow(ax, 14.0, 4.45, 11.8, 4.45)
    draw_arrow(ax, 11.8, 4.45, 8.2, 4.45)

    ax.text(9.0, 9.2, "Figure 5.1: Controlled Attack Simulation Topology", fontsize=14, fontweight="bold", ha="center")
    save_fig("Figure_5_1_simulation_topology.png")


def fig_6_1_latency_trend():
    t = np.arange(1, 11)
    detection = np.array([8.0, 7.6, 7.2, 6.8, 6.4, 6.1, 5.9, 5.7, 5.6, 5.5])
    mitigation = np.array([14, 16, 18, 20, 22, 23, 22, 21, 19, 18])

    plt.figure(figsize=(12, 6))
    plt.plot(t, detection, marker="o", linewidth=2.2, color="#1f77b4", label="Detection latency (s)")
    plt.plot(t, mitigation, marker="s", linewidth=2.2, color="#d62728", label="Mitigation stabilization (s)")
    plt.fill_between(t, detection, mitigation, color="#f5c6c6", alpha=0.2)

    plt.title("Figure 6.1: Detection Latency and Mitigation Response Trend", fontsize=13, fontweight="bold")
    plt.xlabel("Test run")
    plt.ylabel("Time (seconds)")
    plt.grid(alpha=0.3)
    plt.legend()
    save_fig("Figure_6_1_latency_mitigation_trend.png")


def fig_6_2_throughput_behavior():
    categories = ["Normal\nTraffic", "Under Attack\n(Without Mitigation)", "Under Attack\n(With Mitigation)"]
    throughput = [8500, 9800, 80]

    plt.figure(figsize=(12, 6))
    bars = plt.bar(categories, throughput, color=["#2ca02c", "#ff7f0e", "#1f77b4"], edgecolor="#2c3e50")

    for b, val in zip(bars, throughput):
        plt.text(b.get_x() + b.get_width() / 2, val + (120 if val > 200 else 10), f"{val} req/s", ha="center", fontsize=10)

    plt.title("Figure 6.2: Throughput Behavior Under Nominal and Attack Scenarios", fontsize=13, fontweight="bold")
    plt.ylabel("Requests per second")
    plt.grid(axis="y", alpha=0.25)
    save_fig("Figure_6_2_throughput_behavior.png")


def main():
    plt.rcParams["font.family"] = "DejaVu Sans"
    plt.rcParams["font.size"] = 10

    fig_4_1_architecture()
    fig_4_2_data_flow()
    fig_4_3_state_diagram()
    fig_4_4_use_case()
    fig_4_5_sequence()
    fig_5_1_simulation_topology()
    fig_6_1_latency_trend()
    fig_6_2_throughput_behavior()

    print(f"Generated 8 figures in: {OUT_DIR}")


if __name__ == "__main__":
    main()
