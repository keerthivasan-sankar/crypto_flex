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

    # 1. keygen with argon2id
    ret = main(["keygen", "--key", key_file, "--bundle", bundle_file, "--password", password, "--kdf", "argon2id", "--constraint", "fast"])
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

    # keygen with scrypt
    assert main(["keygen", "--key", key_file, "--bundle", bundle_file, "--password", password, "--kdf", "scrypt"]) == 0

    # encrypt --stream
    assert main(["encrypt", "--in", input_file, "--out", enc_file, "--bundle", bundle_file, "--stream"]) == 0

    # decrypt --stream
    assert main(["decrypt", "--in", enc_file, "--out", dec_file, "--key", key_file, "--password", password, "--stream"]) == 0

    with open(dec_file, "rb") as f:
        assert f.read() == original_data


def test_cli_migrate_workflow(tmp_path):
    key1_file = str(tmp_path / "key1.cflk")
    bundle1_file = str(tmp_path / "bundle1.json")
    key2_file = str(tmp_path / "key2.cflk")
    bundle2_file = str(tmp_path / "bundle2.json")

    input_file = str(tmp_path / "original.txt")
    enc1_file = str(tmp_path / "enc1.cflx")
    migrated_file = str(tmp_path / "migrated.cflx")
    dec_file = str(tmp_path / "dec_migrated.txt")

    password = "MigrationTestPassword123"
    content = b"Content to be migrated across bundles"

    with open(input_file, "wb") as f:
        f.write(content)

    # Keygen 1 & Keygen 2
    assert main(["keygen", "--key", key1_file, "--bundle", bundle1_file, "--password", password]) == 0
    assert main(["keygen", "--key", key2_file, "--bundle", bundle2_file, "--password", password]) == 0

    # Encrypt with bundle 1
    assert main(["encrypt", "--in", input_file, "--out", enc1_file, "--bundle", bundle1_file]) == 0

    # Migrate enc1.cflx -> migrated.cflx using key1 to decrypt and bundle2 to re-encrypt
    assert main(["migrate", "--in", enc1_file, "--out", migrated_file, "--key", key1_file, "--new-bundle", bundle2_file, "--password", password]) == 0

    # Decrypt migrated file with key2
    assert main(["decrypt", "--in", migrated_file, "--out", dec_file, "--key", key2_file, "--password", password]) == 0

    with open(dec_file, "rb") as f:
        assert f.read() == content


def test_cli_migrate_streaming_workflow(tmp_path):
    key1_file = str(tmp_path / "stream_key1.cflk")
    bundle1_file = str(tmp_path / "stream_bundle1.json")
    key2_file = str(tmp_path / "stream_key2.cflk")
    bundle2_file = str(tmp_path / "stream_bundle2.json")

    input_file = str(tmp_path / "stream_orig.bin")
    enc1_file = str(tmp_path / "stream_enc1.cflx")
    migrated_file = str(tmp_path / "stream_migrated.cflx")
    dec_file = str(tmp_path / "stream_dec.bin")

    password = "StreamMigratePassword456"
    content = b"Large Stream Payload for Migration Test " * 500

    with open(input_file, "wb") as f:
        f.write(content)

    assert main(["keygen", "--key", key1_file, "--bundle", bundle1_file, "--password", password]) == 0
    assert main(["keygen", "--key", key2_file, "--bundle", bundle2_file, "--password", password]) == 0

    # Encrypt stream with bundle 1
    assert main(["encrypt", "--in", input_file, "--out", enc1_file, "--bundle", bundle1_file, "--stream"]) == 0

    # Migrate stream enc1.cflx -> migrated.cflx --stream
    assert main(["migrate", "--in", enc1_file, "--out", migrated_file, "--key", key1_file, "--new-bundle", bundle2_file, "--password", password, "--stream"]) == 0

    # Decrypt migrated stream with key2
    assert main(["decrypt", "--in", migrated_file, "--out", dec_file, "--key", key2_file, "--password", password, "--stream"]) == 0

    with open(dec_file, "rb") as f:
        assert f.read() == content

