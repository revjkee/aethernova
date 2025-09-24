import os
import logging
import tempfile
from typing import Literal, Optional
from pydantic import BaseModel, validator

from .utils.zk_config import ZK_PROVING_KEYS, ZK_VERIFICATION_KEYS
from .utils.zk_backend import ZKGroth16, ZKPLONK
from .utils.zk_exceptions import ZKProofGenerationError, ZKUnsupportedScheme

logger = logging.getLogger("zk_proof_generator")
logger.setLevel(logging.INFO)

class ZKProofRequest(BaseModel):
    circuit_name: str
    witness_data: dict
    scheme: Literal["groth16", "plonk"]

    @validator("circuit_name")
    def validate_circuit_name(cls, name):
        if name not in ZK_PROVING_KEYS:
            raise ValueError(f"Unknown circuit name: {name}")
        return name


class ZKProofResponse(BaseModel):
    proof: bytes
    public_inputs: list
    scheme: str
    circuit_name: str


class ZKProofGenerator:
    def __init__(self):
        self._backends = {
            "groth16": ZKGroth16(),
            "plonk": ZKPLONK(),
        }

    def generate_proof(self, request: ZKProofRequest) -> ZKProofResponse:
        logger.info(f"Starting ZK proof generation for circuit: {request.circuit_name}, scheme: {request.scheme}")
        
        backend = self._get_backend(request.scheme)
        proving_key = ZK_PROVING_KEYS[request.circuit_name]

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                witness_path = self._write_witness_file(tmpdir, request.witness_data)
                proof, public_inputs = backend.generate(
                    circuit_name=request.circuit_name,
                    witness_path=witness_path,
                    proving_key_path=proving_key,
                    tmp_dir=tmpdir,
                )
        except Exception as e:
            logger.exception("ZK proof generation failed")
            raise ZKProofGenerationError(str(e))

        logger.info("ZK proof generation complete")
        return ZKProofResponse(
            proof=proof,
            public_inputs=public_inputs,
            scheme=request.scheme,
            circuit_name=request.circuit_name,
        )

    def _get_backend(self, scheme: str):
        if scheme not in self._backends:
            raise ZKUnsupportedScheme(f"Unsupported scheme: {scheme}")
        return self._backends[scheme]

    def _write_witness_file(self, tmpdir: str, witness_data: dict) -> str:
        path = os.path.join(tmpdir, "witness.json")
        with open(path, "w") as f:
            import json
            json.dump(witness_data, f)
        return path
