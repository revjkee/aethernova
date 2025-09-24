# TeslaAI Genesis — Risk Matrix Heatmap Generator
# Версия: Industrial v7.3
# Поддержка: SVG, PNG, цветовая кодировка TeslaAI, CVSS классификация, CLI и API

import os
import json
import yaml
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import ListedColormap
from datetime import datetime

RISK_LEVELS = {
    "CRITICAL": {"color": "#d50000", "score": (9.0, 10.0)},
    "HIGH": {"color": "#ef6c00", "score": (7.0, 8.9)},
    "MEDIUM": {"color": "#fbc02d", "score": (4.0, 6.9)},
    "LOW": {"color": "#43a047", "score": (0.1, 3.9)},
    "INFO": {"color": "#0288d1", "score": (0.0, 0.0)}
}

GRID_SIZE = (5, 5)
DEFAULT_OUTPUT_DIR = "out"

def classify_score(score: float) -> str:
    for level, config in RISK_LEVELS.items():
        low, high = config["score"]
        if low <= score <= high:
            return level
    return "INFO"

def load_risk_data(file_path: str):
    if file_path.endswith(".json"):
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    elif file_path.endswith(".yaml") or file_path.endswith(".yml"):
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    else:
        raise ValueError("Unsupported file type")

def generate_heatmap(data, title="Risk Matrix", output_format="svg", output_path=DEFAULT_OUTPUT_DIR):
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    fig, ax = plt.subplots(figsize=(10, 8))
    cmap = ListedColormap([RISK_LEVELS[k]["color"] for k in RISK_LEVELS])

    grid_data = [[None for _ in range(GRID_SIZE[0])] for _ in range(GRID_SIZE[1])]

    for item in data["risks"]:
        x, y = item.get("x", 0), item.get("y", 0)
        score = item.get("score", 0.0)
        label = item.get("id", "")
        level = classify_score(score)
        color = RISK_LEVELS[level]["color"]

        ax.add_patch(
            mpatches.Rectangle((x, y), 1, 1, facecolor=color, edgecolor="black")
        )
        ax.text(x + 0.5, y + 0.5, f"{label}\n{score:.1f}", ha='center', va='center', fontsize=8)

    ax.set_xlim(0, GRID_SIZE[0])
    ax.set_ylim(0, GRID_SIZE[1])
    ax.set_xticks(range(GRID_SIZE[0]))
    ax.set_yticks(range(GRID_SIZE[1]))
    ax.set_title(title, fontsize=14)
    ax.set_aspect('equal')

    legend_handles = [
        mpatches.Patch(color=RISK_LEVELS[l]["color"], label=l)
        for l in RISK_LEVELS
    ]
    ax.legend(handles=legend_handles, loc="upper right")

    filename = f"{title.replace(' ', '_').lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{output_format}"
    filepath = os.path.join(output_path, filename)
    plt.savefig(filepath, format=output_format, bbox_inches="tight")
    plt.close()
    print(f"[✓] Risk heatmap saved to: {filepath}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TeslaAI Risk Heatmap Generator")
    parser.add_argument("file", help="Path to YAML or JSON risk data")
    parser.add_argument("--format", choices=["svg", "png"], default="svg", help="Output format")
    parser.add_argument("--title", default="Risk Matrix", help="Title of the heatmap")
    parser.add_argument("--output", default=DEFAULT_OUTPUT_DIR, help="Output directory")

    args = parser.parse_args()

    data = load_risk_data(args.file)
    generate_heatmap(data, title=args.title, output_format=args.format, output_path=args.output)
