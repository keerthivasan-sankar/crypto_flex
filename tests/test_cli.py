import os
from cryptoflex.cli import main


def test_cli_keygen_encrypt_decrypt_info_workflow(tmp_path):
    key_file = str(tmp_path / "test.cflk")
    bundle_file = str(tmp_path / "test_bundle.json")
    input_file = str(tmp_path / "input.txt")
    enc_file = str(tmp_path / "enc.cflx")
    dec_file = str(tmp_path / "dec.txt")

    password = "CliTestPassword99"
    original_text = b"CLI End-To-End Integration Verification Message!"

    with open(input_file, "wb") as f:
        f.write(original_text)

    # 1. keygen
    ret = main(["keygen", "--key", key_file, "--bundle", bundle_file, "--password", password, "--constraint", "fast"])
    assert ret == 0
    assert os.path.exists(key_file)
    assert os.path.exists(bundle_file)

    # 2. encrypt (regular)
    ret = main(["encrypt", "--in", input_file, "--out", enc_file, "--bundle", bundle_file])
    assert ret == 0
    assert os.path.exists(enc_file)

    # 3. info
    ret = main(["info", enc_file])
    assert ret == 0

    # 4. decrypt (regular)
    ret = main(["decrypt", "--in", enc_file, "--out", dec_file, "--key", key_file, "--password", password])
    assert ret == 0

    with open(dec_file, "rb") as f:
        assert f.read() == original_text


def test_cli_streaming_workflow(tmp_path):
    key_file = str(tmp_path / "stream_test.cflk")
    bundle_file = str(tmp_path / "stream_bundle.json")
    input_file = str(tmp_path / "stream_input.bin")
    enc_file = str(tmp_path / "stream_enc.cflx")
    dec_file = str(tmp_path / "stream_dec.bin")

    password = "StreamPassword123"
    original_data = b"STREAMING CLI DATA BLOCK " * 1000

    with open(input_file, "wb") as f:
        f.write(original_data)

    # keygen
    assert main(["keygen", "--key", key_file, "--bundle", bundle_file, "--password", password]) == 0

    # encrypt --stream
    assert main(["encrypt", "--in", input_file, "--out", enc_file, "--bundle", bundle_file, "--stream"]) == 0

    # decrypt --stream
    assert main(["decrypt", "--in", enc_file, "--out", dec_file, "--key", key_file, "--password", password, "--stream"]) == 0

    with open(dec_file, "rb") as f:
        assert f.read() == original_data
