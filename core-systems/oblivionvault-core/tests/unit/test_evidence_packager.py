# oblivionvault-core/tests/unit/test_evidence_packager.py
import io
import json
import os
import sys
import zipfile
import hashlib
import platform
from pathlib import Path
from contextlib import contextmanager

import pytest

# Тестируем целевой модуль
from oblivionvault.cli.tools import generate_evidence as ev


def _make_tree(root: Path) -> dict:
    """
    Создать небольшое дерево файлов для тестов.
    Возвращает словарь с путями полезных файлов.
    """
    files = {}
    (root / "sub").mkdir(parents=True, exist_ok=True)

    p1 = root / "a.txt"
    p1.write_text("hello oblivionvault\n", encoding="utf-8")
    files["a"] = p1

    p2 = root / "sub" / "b.bin"
    p2.write_bytes(os.urandom(1024))
    files["b"] = p2

    p3 = root / "logfile.log"
    p3.write_text("log line 1\n", encoding="utf-8")
    files["log"] = p3

    p4 = root / ".hidden"
    p4.write_text("secret\n", encoding="utf-8")  # по умолчанию не должен попасть
    files["hidden"] = p4

    # Символическая ссылка (может не поддерживаться на Windows без прав)
    files["symlink"] = None
    try:
        link = root / "link_to_a"
        if link.exists():
            link.unlink()
        link.symlink_to(p1)
        files["symlink"] = link
    except Exception:
        # Безопасно игнорируем — тесты учитывают возможность отсутствия symlink
        pass

    return files


def _args_generate(
    tmp_path: Path,
    inputs,
    *,
    out_name="bundle.zip",
    embed=False,
    exclude=None,
    follow_symlinks=False,
    allow_hidden=False,
    workers=2,
    label="test",
    include_sbom=False,
    sign=False,
    sign_pem=None,
):
    return type(
        "Args",
        (),
        dict(
            inputs=[str(p) for p in inputs],
            out=str(tmp_path / out_name),
            exclude=list(exclude or []),
            follow_symlinks=bool(follow_symlinks),
            allow_hidden=bool(allow_hidden),
            workers=int(workers),
            embed_files=bool(embed),
            label=label,
            include_sbom=bool(include_sbom),
            sign=bool(sign),
            sign_pem=str(sign_pem) if sign_pem else None,
        ),
    )()


def _args_verify(bundle: Path, root: Path | None = None):
    return type("Args", (), dict(bundle=str(bundle), root=str(root) if root else None))()


def _args_show(bundle: Path):
    return type("Args", (), dict(bundle=str(bundle)))()


def _open_manifest(bundle: Path) -> dict:
    with zipfile.ZipFile(str(bundle), "r") as zf:
        data = zf.read("manifest.json")
    return json.loads(data.decode("utf-8"))


def _first_embedded_arcname(bundle: Path) -> str | None:
    with zipfile.ZipFile(str(bundle), "r") as zf:
        for n in zf.namelist():
            if n.startswith("files/") and not n.endswith("/"):
                return n
    return None


def _copy_zip_with_replaced_file(src: Path, dst: Path, arcname_to_replace: str, new_bytes: bytes):
    """
    Создать новый zip на основе src, заменив один файл.
    """
    with zipfile.ZipFile(str(src), "r") as zin, zipfile.ZipFile(str(dst), "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zout:
        for item in zin.infolist():
            if item.filename == arcname_to_replace:
                zout.writestr(item.filename, new_bytes)
            else:
                zout.writestr(item, zin.read(item.filename))


def test_generate_and_verify_embedded(tmp_path: Path):
    files = _make_tree(tmp_path / "src")
    args = _args_generate(tmp_path, [tmp_path / "src"], embed=True, exclude=["**/*.log"])
    ev._cmd_generate(args)

    bundle = Path(args.out)
    assert bundle.exists()

    # verify должен пройти без исключений
    ev._cmd_verify(_args_verify(bundle))

    mani = _open_manifest(bundle)
    assert mani["subject"]["attached_files"] is True
    # лог и скрытый файл отсутствуют
    manifest_paths = {f["path"] for f in mani["files"]}
    assert "logfile.log" not in manifest_paths
    assert ".hidden" not in manifest_paths
    # merkle root существует
    assert isinstance(mani["merkle"]["root"], str) and len(mani["merkle"]["root"]) == 64


def test_generate_and_verify_external_with_mutation(tmp_path: Path):
    src = tmp_path / "src"
    files = _make_tree(src)
    args = _args_generate(tmp_path, [src], embed=False, exclude=["**/*.log"])
    ev._cmd_generate(args)
    bundle = Path(args.out)
    assert bundle.exists()

    # Успешная верификация против исходного дерева
    ev._cmd_verify(_args_verify(bundle, root=src))

    # Мутация исходного файла — должна сломать verify
    (src / "a.txt").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(SystemExit) as ei:
        ev._cmd_verify(_args_verify(bundle, root=src))
    assert "Verification failed" in str(ei.value)


def test_filters_hidden_and_symlink_excluded_by_default(tmp_path: Path):
    src = tmp_path / "src"
    files = _make_tree(src)
    args = _args_generate(tmp_path, [src], embed=True, exclude=["**/*.log"], follow_symlinks=False, allow_hidden=False)
    ev._cmd_generate(args)
    bundle = Path(args.out)

    mani = _open_manifest(bundle)
    paths = {f["path"] for f in mani["files"]}
    assert ".hidden" not in paths
    assert "logfile.log" not in paths
    # symlink не попадает, если он вообще был создан на платформе
    if files["symlink"] is not None:
        assert "link_to_a" not in paths


@pytest.mark.parametrize("embed", [False, True])
def test_merkle_is_deterministic(tmp_path: Path, embed: bool):
    src = tmp_path / "src"
    _make_tree(src)

    args1 = _args_generate(tmp_path, [src], embed=embed, out_name="b1.zip")
    args2 = _args_generate(tmp_path, [src], embed=embed, out_name="b2.zip")

    ev._cmd_generate(args1)
    ev._cmd_generate(args2)

    m1 = _open_manifest(Path(args1.out))
    m2 = _open_manifest(Path(args2.out))

    assert m1["merkle"]["root"] == m2["merkle"]["root"]
    assert m1["merkle"]["leaf_order"] == m2["merkle"]["leaf_order"]


@pytest.mark.skipif(not ev.CRYPTO_AVAILABLE, reason="cryptography is not available")
def test_signature_roundtrip_ed25519(tmp_path: Path):
    # Генерируем ключ и подписываем бандл
    priv, pub = ev.Ed25519Signer.generate()
    pem_path = tmp_path / "ed25519_sk.pem"
    ev.Ed25519Signer.save_pem(priv, pem_path)

    src = tmp_path / "src"
    _make_tree(src)

    args = _args_generate(tmp_path, [src], embed=True, sign_pem=pem_path)
    ev._cmd_generate(args)
    bundle = Path(args.out)

    mani = _open_manifest(bundle)
    assert mani.get("signature") and mani["signature"].get("alg") == "Ed25519"

    # Проверка подписи на уровне модуля
    manifest_obj, zf = ev.load_manifest_from_zip(bundle)
    try:
        assert ev.verify_manifest_signature(manifest_obj) is True
    finally:
        zf.close()

    # Проверка вручную через публичный ключ
    data = dict(mani)
    sig = data.pop("signature")
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert ev.Ed25519Signer.verify(sig["public_key_b64"], payload, sig["signature_b64"]) is True


def test_show_outputs_valid_json(tmp_path: Path, capsys):
    src = tmp_path / "src"
    _make_tree(src)
    args = _args_generate(tmp_path, [src], embed=True)
    ev._cmd_generate(args)

    ev.cmd_show(_args_show(Path(args.out)))
    out = capsys.readouterr().out
    obj = json.loads(out)
    assert obj["schema"].startswith("https://")
    assert "files" in obj and isinstance(obj["files"], list)


def test_verify_fails_on_corrupted_embedded_data(tmp_path: Path):
    src = tmp_path / "src"
    _make_tree(src)
    args = _args_generate(tmp_path, [src], embed=True)
    ev._cmd_generate(args)
    bundle = Path(args.out)

    # Заменим первый embedded-файл на другие байты, не трогая manifest.json
    arcname = _first_embedded_arcname(bundle)
    assert arcname is not None
    corrupt = tmp_path / "bundle_corrupt.zip"
    _copy_zip_with_replaced_file(bundle, corrupt, arcname, b"CORRUPTED_BYTES")

    with pytest.raises(SystemExit) as ei:
        ev._cmd_verify(_args_verify(corrupt))
    assert "Verification failed" in str(ei.value)


def test_exclude_globs_and_allow_hidden_flag(tmp_path: Path):
    src = tmp_path / "src"
    _make_tree(src)
    # Теперь включим скрытые файлы и расширим exclude
    args = _args_generate(
        tmp_path,
        [src],
        embed=True,
        allow_hidden=True,
        exclude=["**/*.log", "**/b.bin"],
    )
    ev._cmd_generate(args)
    mani = _open_manifest(Path(args.out))
    paths = {f["path"] for f in mani["files"]}
    # .hidden теперь допустим, но b.bin и logfile.log исключены
    assert ".hidden" in paths
    assert "sub/b.bin" not in paths
    assert "logfile.log" not in paths


def test_verify_detects_merkle_root_mismatch_on_manifest_change(tmp_path: Path):
    src = tmp_path / "src"
    _make_tree(src)
    args = _args_generate(tmp_path, [src], embed=True)
    ev._cmd_generate(args)
    bundle = Path(args.out)

    # Изменим manifest.json (портим merkle.root) и соберём новый архив
    with zipfile.ZipFile(str(bundle), "r") as zin:
        mani = json.loads(zin.read("manifest.json").decode("utf-8"))
        mani["merkle"]["root"] = "0" * 64  # заведомо неверный
        altered = tmp_path / "bundle_merkle_bad.zip"
        with zipfile.ZipFile(str(altered), "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zout:
            for item in zin.infolist():
                if item.filename == "manifest.json":
                    zout.writestr("manifest.json", json.dumps(mani, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                else:
                    zout.writestr(item, zin.read(item.filename))

    with pytest.raises(SystemExit) as ei:
        ev._cmd_verify(_args_verify(altered))
    assert "Verification failed" in str(ei.value)
