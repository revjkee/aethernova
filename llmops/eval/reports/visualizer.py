import os
import json
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, Any, Optional, List
from ..utils import logger

sns.set(style="whitegrid")


class MetricVisualizer:
    def __init__(
        self,
        output_dir: str = "eval/visuals",
        figsize: tuple = (10, 6),
        palette: str = "muted"
    ):
        self.output_dir = output_dir
        self.figsize = figsize
        self.palette = palette
        os.makedirs(self.output_dir, exist_ok=True)
        logger.debug(f"Visualizer initialized, output dir: {self.output_dir}")

    def plot_metric_bars(
        self,
        data: Dict[str, float],
        title: str = "Metric Comparison",
        ylabel: str = "Score",
        filename: str = "metric_bars.png"
    ):
        logger.debug("Plotting metric bars")
        keys, values = zip(*sorted(data.items(), key=lambda x: x[1], reverse=True))

        plt.figure(figsize=self.figsize)
        sns.barplot(x=list(values), y=list(keys), palette=self.palette)
        plt.title(title)
        plt.xlabel(ylabel)
        plt.tight_layout()

        path = os.path.join(self.output_dir, filename)
        plt.savefig(path)
        plt.close()
        logger.info(f"Saved barplot: {path}")

    def plot_heatmap(
        self,
        data: Dict[str, Dict[str, float]],
        title: str = "Metric Heatmap",
        filename: str = "metric_heatmap.png"
    ):
        logger.debug("Plotting heatmap")
        if not data:
            logger.warning("No data for heatmap")
            return

        plt.figure(figsize=(max(10, len(data) * 1.2), len(next(iter(data.values()))) + 2))
        sns.heatmap(
            [list(metrics.values()) for metrics in data.values()],
            annot=True,
            xticklabels=list(next(iter(data.values())).keys()),
            yticklabels=list(data.keys()),
            cmap="viridis",
            fmt=".2f"
        )
        plt.title(title)
        plt.tight_layout()

        path = os.path.join(self.output_dir, filename)
        plt.savefig(path)
        plt.close()
        logger.info(f"Saved heatmap: {path}")

    def export_json(
        self,
        data: Dict[str, Any],
        filename: str = "aggregated_results.json"
    ):
        logger.debug("Exporting metrics to JSON")
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logger.info(f"Exported JSON: {path}")

    def plot_task_comparison(
        self,
        all_results: Dict[str, Dict[str, float]],
        metric: str,
        filename: str = "task_comparison.png"
    ):
        logger.debug(f"Plotting task comparison for metric: {metric}")
        values = {task: scores.get(metric, 0.0) for task, scores in all_results.items()}
        self.plot_metric_bars(
            values,
            title=f"{metric} by Task",
            ylabel=metric,
            filename=filename
        )
