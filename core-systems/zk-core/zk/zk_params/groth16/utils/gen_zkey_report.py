import json
import sys

def load_zkey(filename):
    with open(filename, "r") as f:
        return json.load(f)

def analyze_constraints(zkey_data):
    constraints = zkey_data.get("constraints", [])
    num_constraints = len(constraints)
    return num_constraints

def analyze_signals(zkey_data):
    signals = zkey_data.get("signals", [])
    num_signals = len(signals)
    return num_signals

def main():
    if len(sys.argv) != 2:
        print(f"Использование: {sys.argv[0]} <zkey_file.json>")
        sys.exit(1)
    
    zkey_file = sys.argv[1]
    zkey_data = load_zkey(zkey_file)

    num_constraints = analyze_constraints(zkey_data)
    num_signals = analyze_signals(zkey_data)

    print(f"Отчет по ZKey-файлу: {zkey_file}")
    print(f"Количество constraints: {num_constraints}")
    print(f"Количество signals: {num_signals}")

if __name__ == "__main__":
    main()
