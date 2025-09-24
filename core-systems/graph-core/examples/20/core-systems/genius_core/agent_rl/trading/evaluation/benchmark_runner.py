# agent_rl/trading/evaluation/benchmark_runner.py

import os
import pandas as pd
from agent_rl.trading.evaluation.eval_metrics import evaluate_all_metrics
from typing import List, Dict
from termcolor import cprint


class StrategyBenchmarkRunner:
    def __init__(self, results_dir: str, output_csv: str = "benchmark_summary.csv"):
        self.results_dir = results_dir
        self.output_csv = output_csv
        self.results = []

    def run_benchmark(self) -> pd.DataFrame:
        strategy_files = [f for f in os.listdir(self.results_dir) if f.endswith(".csv")]
        for file in strategy_files:
            strategy_name = os.path.splitext(file)[0]
            file_path = os.path.join(self.results_dir, file)
            try:
                df = pd.read_csv(file_path)
                metrics = evaluate_all_metrics(
                    returns=df["returns"],
                    equity_curve=df["equity"]
                )
                metrics["Strategy"] = strategy_name
                self.results.append(metrics)
                cprint(f"[✓] Evaluated: {strategy_name}", "green")
            except Exception as e:
                cprint(f"[x] Failed: {strategy_name} — {str(e)}", "red")

        result_df = pd.DataFrame(self.results)
        result_df.sort_values(by="Sharpe Ratio", ascending=False, inplace=True)
        result_df.to_csv(self.output_csv, index=False)
        cprint(f"[✔] Benchmark complete. Saved to: {self.output_csv}", "cyan")
        return result_df

    def print_leaderboard(self, top_n: int = 5):
        df = pd.DataFrame(self.results)
        df = df.sort_values(by="Sharpe Ratio", ascending=False).head(top_n)
        cprint(f"\n=== TOP-{top_n} STRATEGIES ===", "blue")
        print(df[["Strategy", "Sharpe Ratio", "PnL", "Sortino Ratio", "Max Drawdown", "Volatility", "MAR Ratio"]])
