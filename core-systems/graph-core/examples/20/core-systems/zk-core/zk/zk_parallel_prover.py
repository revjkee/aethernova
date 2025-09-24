# zk-core/zk/zk_parallel_prover.py

import multiprocessing
import asyncio
from concurrent.futures import ProcessPoolExecutor
from typing import Callable, List, Dict, Any

from .zk_proof_engines import Groth16Prover, PlonkProver, StarkProver  # условно абстрагированы
from .zk_models import ZKProofRequest, ZKProofResult


class ProverManager:
    """
    Распараллеленный ZK-генератор доказательств для масштабных систем.
    """

    def __init__(self, max_workers: int = multiprocessing.cpu_count()):
        self.executor = ProcessPoolExecutor(max_workers=max_workers)
        self.loop = asyncio.get_event_loop()
        self.backends: Dict[str, Callable] = {
            "groth16": Groth16Prover().generate_proof,
            "plonk": PlonkProver().generate_proof,
            "stark": StarkProver().generate_proof,
        }

    async def _run_async_proof(self, prover_func: Callable, request: ZKProofRequest) -> ZKProofResult:
        return await self.loop.run_in_executor(self.executor, prover_func, request)

    async def generate_batch_proofs(self, requests: List[ZKProofRequest]) -> List[ZKProofResult]:
        """
        Генерация партии доказательств с использованием асинхронного и многопроцессного исполнения.
        """
        tasks = []
        for req in requests:
            prover_func = self.backends.get(req.scheme)
            if not prover_func:
                raise ValueError(f"Unknown ZK scheme: {req.scheme}")
            tasks.append(self._run_async_proof(prover_func, req))
        return await asyncio.gather(*tasks)

    def shutdown(self):
        self.executor.shutdown()


# Пример использования
if __name__ == "__main__":
    import time

    manager = ProverManager()

    sample_requests = [
        ZKProofRequest(
            scheme="groth16",
            circuit_path="circuits/hash.circom",
            inputs={"x": 1, "y": 2}
        ),
        ZKProofRequest(
            scheme="plonk",
            circuit_path="circuits/sigverify.circom",
            inputs={"pubkey": "0xabc", "msg": "hello", "sig": "0x123"}
        ),
        ZKProofRequest(
            scheme="stark",
            circuit_path="circuits/fibonacci.circom",
            inputs={"n": 20}
        ),
    ]

    start_time = time.time()
    results = asyncio.run(manager.generate_batch_proofs(sample_requests))
    end_time = time.time()

    for res in results:
        print(f"[{res.scheme.upper()}] Valid: {res.valid} | Proof: {res.proof_path}")
    print(f"Total time: {end_time - start_time:.2f}s")

    manager.shutdown()
