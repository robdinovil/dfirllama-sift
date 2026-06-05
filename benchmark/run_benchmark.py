#!/usr/bin/env python3
"""
DFIRLlama-SIFT — Benchmark de Accuracy
========================================
Mide la precisión del motor NL→SQL (query_evtx_nl_tool) sobre datasets
forenses con respuestas de ground truth conocidas.

Genera métricas compatibles con DFIR-Metric (arxiv 2505.19973) y AutoDFBench
(arxiv 2512.16965): Precision, Recall, F1, Execution Accuracy, Hallucination Rate.

Uso:
    python3 benchmark/run_benchmark.py --db demo/data/tslsm_demo.db
    python3 benchmark/run_benchmark.py --db demo/data/tslsm_demo.db --model qwen2.5:14b
    python3 benchmark/run_benchmark.py --db demo/data/tslsm_demo.db --dry-run
"""

import argparse
import json
import os
import sys
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from benchmark.ground_truth import TSLSM_QUESTIONS, DATASET_METADATA

BOLD  = "\033[1m"
GREEN = "\033[92m"
RED   = "\033[91m"
YELLOW= "\033[93m"
CYAN  = "\033[96m"
RESET = "\033[0m"


# ── Evaluador de respuestas ───────────────────────────────────────────────────

def evaluate_result(question: dict, sql_generated: str,
                    df_result: pd.DataFrame | None) -> dict:
    """
    Compara el resultado de la SQL generada contra el ground truth.
    Retorna: correct (bool), partial (bool), explanation (str).
    """
    if df_result is None or df_result.empty:
        return {"correct": False, "partial": False,
                "explanation": "Query produjo resultado vacío"}

    expected_type  = question["expected_type"]
    expected_value = question["expected_value"]
    expected_cont  = question.get("expected_contains", "")

    result_str = df_result.to_string(index=False)

    # ── Verificación por tipo esperado ────────────────────────────────────────

    if expected_type == "count":
        try:
            got = int(df_result.iloc[0, 0])
            if got == expected_value:
                return {"correct": True, "partial": False,
                        "explanation": f"Exact match: {got}"}
            elif abs(got - expected_value) / max(expected_value, 1) < 0.05:
                return {"correct": False, "partial": True,
                        "explanation": f"Near miss: got {got}, expected {expected_value} (within 5%)"}
            else:
                return {"correct": False, "partial": False,
                        "explanation": f"Wrong count: got {got}, expected {expected_value}"}
        except (ValueError, TypeError):
            pass

    elif expected_type in ("timestamp", "value"):
        if expected_cont and expected_cont in result_str:
            return {"correct": True, "partial": False,
                    "explanation": f"Expected value '{expected_cont}' found in result"}
        return {"correct": False, "partial": False,
                "explanation": f"Expected '{expected_cont}' not found in: {result_str[:100]}"}

    elif expected_type == "list_values":
        if isinstance(expected_value, list):
            found = sum(1 for v in expected_value if v in result_str)
            total = len(expected_value)
            if found == total:
                return {"correct": True, "partial": False,
                        "explanation": f"All {total} expected values found"}
            elif found > 0:
                return {"correct": False, "partial": True,
                        "explanation": f"{found}/{total} expected values found"}
        if expected_cont and expected_cont in result_str:
            return {"correct": False, "partial": True,
                    "explanation": f"Key value '{expected_cont}' found but not all expected"}

    elif expected_type == "list_dates":
        if isinstance(expected_value, list):
            found = sum(1 for d in expected_value if d in result_str)
            total = len(expected_value)
            if found == total:
                return {"correct": True, "partial": False,
                        "explanation": f"All {total} expected dates found"}
            elif found > 0:
                return {"correct": False, "partial": True,
                        "explanation": f"{found}/{total} dates found"}

    elif expected_type in ("range", "distribution", "list_with_counts"):
        if expected_cont and expected_cont in result_str:
            return {"correct": True, "partial": False,
                    "explanation": f"Key value '{expected_cont}' present in result"}

    return {"correct": False, "partial": False,
            "explanation": f"Result did not match expected for type '{expected_type}'"}


def check_hallucination(sql: str, db_path: str) -> dict:
    """
    Verifica si el SQL generado es ejecutable y si referencia columnas reales.
    Una alucinación estructural = SQL que referencia tablas/columnas inexistentes.
    """
    if not sql:
        return {"hallucinated": True, "type": "empty_sql", "detail": "No SQL generated"}

    try:
        conn = sqlite3.connect(db_path)
        # Verificar que las tablas referenciadas existen
        tables_in_db = pd.read_sql(
            "SELECT name FROM sqlite_master WHERE type='table'", conn
        )["name"].tolist()

        # Intento de EXPLAIN (valida SQL sin ejecutar)
        conn.execute(f"EXPLAIN {sql}")
        conn.close()
        return {"hallucinated": False, "type": None, "detail": "SQL válido y ejecutable"}
    except sqlite3.OperationalError as e:
        error = str(e)
        if "no such column" in error:
            return {"hallucinated": True, "type": "invented_column",
                    "detail": f"Columna inexistente: {error}"}
        elif "no such table" in error:
            return {"hallucinated": True, "type": "invented_table",
                    "detail": f"Tabla inexistente: {error}"}
        else:
            return {"hallucinated": True, "type": "syntax_error",
                    "detail": f"SQL inválido: {error}"}
    except Exception as e:
        return {"hallucinated": True, "type": "execution_error", "detail": str(e)}


# ── Runner principal ──────────────────────────────────────────────────────────

def run_nlsql_query(vn, question_text: str, db_path: str,
                    dry_run: bool = False) -> tuple[str | None, pd.DataFrame | None, float]:
    """
    Corre una pregunta contra Vanna y retorna (sql, resultado, tiempo_segundos).
    """
    if dry_run:
        # Modo dry-run: ejecutar SQL de ground truth directamente
        return None, None, 0.0

    t0  = time.time()
    try:
        sql = vn.generate_sql(question_text)
        if not sql:
            return None, None, time.time() - t0

        conn = sqlite3.connect(db_path)
        df   = pd.read_sql(sql, conn)
        conn.close()
        return sql, df, time.time() - t0
    except Exception as e:
        return None, None, time.time() - t0


def run_benchmark(db_path: str, model: str = "qwen2.5:14b",
                  dry_run: bool = False, output_file: str | None = None):

    print(f"\n{CYAN}{BOLD}DFIRLlama-SIFT — NL→SQL Accuracy Benchmark{RESET}")
    print(f"{CYAN}Dataset: {DATASET_METADATA['name']} | {DATASET_METADATA['total_rows']} eventos{RESET}")
    print(f"{CYAN}Modelo:  {model} | DB: {db_path}{RESET}")
    if dry_run:
        print(f"{YELLOW}[DRY RUN] — ejecutando SQL de ground truth directamente{RESET}")
    print(f"{'─'*70}\n")

    # Inicializar Vanna (si no es dry-run)
    vn = None
    if not dry_run:
        try:
            from vanna.ollama import Ollama
            from vanna.chromadb import ChromaDB_VectorStore

            class LocalVanna(ChromaDB_VectorStore, Ollama):
                def __init__(self, config=None):
                    ChromaDB_VectorStore.__init__(self, config=config)
                    Ollama.__init__(self, config=config)

            vn = LocalVanna(config={
                "model": model,
                "path": "/tmp/dfirllama_benchmark_chroma"
            })
            vn.connect_to_sqlite(db_path)

            # Entrenar con schema + contexto forense básico
            conn = sqlite3.connect(db_path)
            for row in pd.read_sql(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL", conn
            ).itertuples():
                vn.train(ddl=row.sql)
            conn.close()

            vn.train(documentation="EventId 21 = RDP logon exitoso.")
            vn.train(documentation="EventId 22 = shell start, 23 = logoff, 24 = disconnect.")
            vn.train(documentation="RemoteHost con 10.x.x.x = IP interna. Cualquier otra = externa.")
            vn.train(documentation="UserName 'administrator' es la cuenta privilegiada de interés.")
            vn.train(question="¿Cuántos logons exitosos?",
                     sql="SELECT COUNT(*) FROM rdp_activity WHERE EventId=21")
            vn.train(question="¿IPs externas?",
                     sql="SELECT DISTINCT RemoteHost FROM rdp_activity WHERE EventId=21 AND RemoteHost NOT LIKE '10.%'")
        except ImportError:
            print(f"{RED}[!] Vanna no disponible. Usando --dry-run.{RESET}")
            dry_run = True

    # Ejecutar las 20 preguntas
    results        = []
    correct_count  = 0
    partial_count  = 0
    halluc_count   = 0
    total_time     = 0.0

    for i, q in enumerate(TSLSM_QUESTIONS, 1):
        print(f"{BOLD}[{i:02d}/20]{RESET} {q['id']} — {q['question'][:60]}...")

        if dry_run:
            # En dry-run, ejecutar el SQL de ground truth
            try:
                conn = sqlite3.connect(db_path)
                df   = pd.read_sql(q["ground_truth_sql"], conn)
                conn.close()
                sql_gen  = q["ground_truth_sql"]
                elapsed  = 0.001
                halluc   = {"hallucinated": False, "type": None, "detail": "Ground truth SQL"}
            except Exception as e:
                sql_gen, df, elapsed = None, None, 0.0
                halluc = {"hallucinated": True, "type": "gt_error", "detail": str(e)}
        else:
            sql_gen, df, elapsed = run_nlsql_query(vn, q["question"], db_path)
            halluc = check_hallucination(sql_gen or "", db_path)

        total_time += elapsed

        # Evaluar resultado
        eval_result = evaluate_result(q, sql_gen or "", df)

        if halluc["hallucinated"]:
            halluc_count += 1
            status_sym = f"{RED}[HALLU]{RESET}"
            status     = "hallucinated"
        elif eval_result["correct"]:
            correct_count += 1
            status_sym = f"{GREEN}[ OK  ]{RESET}"
            status     = "correct"
        elif eval_result["partial"]:
            partial_count += 1
            status_sym = f"{YELLOW}[PART ]{RESET}"
            status     = "partial"
        else:
            status_sym = f"{RED}[ FAIL]{RESET}"
            status     = "incorrect"

        print(f"        {status_sym} {eval_result['explanation']}")
        if sql_gen and sql_gen != q["ground_truth_sql"] and not dry_run:
            print(f"        SQL: {sql_gen[:80]}...")
        print(f"        Tiempo: {elapsed:.2f}s | Dificultad: {q['difficulty']}")
        print()

        results.append({
            "id":               q["id"],
            "question":         q["question"],
            "category":         q["category"],
            "difficulty":       q["difficulty"],
            "status":           status,
            "correct":          eval_result["correct"],
            "partial":          eval_result["partial"],
            "explanation":      eval_result["explanation"],
            "sql_generated":    sql_gen,
            "ground_truth_sql": q["ground_truth_sql"],
            "hallucinated":     halluc["hallucinated"],
            "hallucination_type": halluc["type"],
            "elapsed_seconds":  round(elapsed, 3),
            "forensic_relevance": q["forensic_relevance"],
        })

    # ── Métricas finales ──────────────────────────────────────────────────────
    total   = len(TSLSM_QUESTIONS)
    wrong   = total - correct_count - partial_count - halluc_count
    exec_accuracy   = correct_count / total
    partial_credit  = (correct_count + 0.5 * partial_count) / total
    halluc_rate     = halluc_count / total

    # Precision, Recall, F1 (tratando correct como TP)
    tp = correct_count
    fp = halluc_count          # respuesta incorrecta con confianza = FP
    fn = wrong + partial_count # respuestas parciales y incorrectas = FN
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"\n{'═'*70}")
    print(f"{BOLD}RESULTADOS FINALES{RESET}")
    print(f"{'═'*70}")
    print(f"  Total preguntas:        {total}")
    print(f"  {GREEN}Correctas:              {correct_count} ({exec_accuracy:.1%}){RESET}")
    print(f"  {YELLOW}Parcialmente correctas: {partial_count}{RESET}")
    print(f"  {RED}Incorrectas:            {wrong}{RESET}")
    print(f"  {RED}Alucinaciones SQL:      {halluc_count} ({halluc_rate:.1%}){RESET}")
    print(f"")
    print(f"  Execution Accuracy:     {exec_accuracy:.3f}  ({exec_accuracy:.1%})")
    print(f"  Partial Credit Score:   {partial_credit:.3f}  ({partial_credit:.1%})")
    print(f"  Precision:              {precision:.3f}")
    print(f"  Recall:                 {recall:.3f}")
    print(f"  F1 Score:               {f1:.3f}")
    print(f"  Hallucination Rate:     {halluc_rate:.3f}  ({halluc_rate:.1%})")
    print(f"  Avg time per query:     {total_time/total:.2f}s")
    print(f"")

    # Breakdown por dificultad
    for diff in ["easy", "medium", "hard"]:
        subset = [r for r in results if TSLSM_QUESTIONS[int(r["id"][1:])-1]["difficulty"] == diff]
        if subset:
            correct_d = sum(1 for r in subset if r["correct"])
            print(f"  {diff.capitalize():8}: {correct_d}/{len(subset)} correctas ({correct_d/len(subset):.0%})")

    print(f"\n  Baseline context (DFIR-Metric 2505.19973):")
    print(f"  — Naive LLM baseline (NIST CFReDS): F1=25.6%")
    print(f"  — DFIRLlama-SIFT NL→SQL:            F1={f1:.1%} (bounded SQL vs direct LLM ingestion)")
    print(f"{'═'*70}\n")

    # Guardar resultados
    output = {
        "benchmark_metadata": {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "model":      model,
            "db_path":    db_path,
            "dry_run":    dry_run,
            "dataset":    DATASET_METADATA,
            "references": [
                "DFIR-Metric (arxiv 2505.19973)",
                "AutoDFBench (arxiv 2512.16965)",
                "NL2SQL Benchmarking (TechRxiv 2024)",
            ],
        },
        "metrics": {
            "total_questions":    total,
            "correct":            correct_count,
            "partial":            partial_count,
            "incorrect":          wrong,
            "hallucinated":       halluc_count,
            "execution_accuracy": round(exec_accuracy, 4),
            "partial_credit":     round(partial_credit, 4),
            "precision":          round(precision, 4),
            "recall":             round(recall, 4),
            "f1_score":           round(f1, 4),
            "hallucination_rate": round(halluc_rate, 4),
            "avg_time_seconds":   round(total_time / total, 3),
        },
        "results": results,
    }

    out_path = output_file or f"./analysis/benchmark_results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"  Resultados guardados: {out_path}")

    return output


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="DFIRLlama-SIFT NL→SQL Benchmark")
    p.add_argument("--db",       default="demo/data/tslsm_demo.db")
    p.add_argument("--model",    default="qwen2.5:14b")
    p.add_argument("--dry-run",  action="store_true",
                   help="Corre SQL de ground truth directamente (sin LLM)")
    p.add_argument("--output",   default=None)
    args = p.parse_args()

    run_benchmark(args.db, args.model, args.dry_run, args.output)
