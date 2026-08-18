import pytest

from cryptoflex.combiner import combine, combine_from_secrets
from cryptoflex.sources import ClassicalSource, MockPQCSource


def _make_hybrid_encapsulations():
    """Simulate a two-source hybrid handshake and return everything needed
    to test both the encapsulation and decapsulation sides."""
    classical = ClassicalSource()
    pqc = MockPQCSource()

    c_pub, c_priv = classical.generate_keypair()
    p_pub, p_priv = pqc.generate_keypair()

    c_enc = classical.encapsulate(c_pub)
    p_enc = pqc.encapsulate(p_pub)

    encapsulations = [("x25519", c_enc), ("mock-pqc-test-only", p_enc)]

    c_secret = classical.decapsulate(c_priv, c_enc.ciphertext)
    p_secret = pqc.decapsulate(p_priv, p_enc.ciphertext)
    shared_secrets = [("x25519", c_secret), ("mock-pqc-test-only", p_secret)]
    ciphertexts = [("x25519", c_enc.ciphertext), ("mock-pqc-test-only", p_enc.ciphertext)]

    return encapsulations, shared_secrets, ciphertexts


def test_combine_requires_nonempty_input():
    with pytest.raises(ValueError):
        combine([])


def test_encapsulation_and_decapsulation_sides_produce_same_root_key():
    encapsulations, shared_secrets, ciphertexts = _make_hybrid_encapsulations()

    encap_side = combine(encapsulations)
    decap_side = combine_from_secrets(shared_secrets, ciphertexts)

    assert encap_side.root_key == decap_side.root_key
    assert len(encap_side.root_key) == 32


def test_combiner_output_changes_if_any_single_secret_changes():
    """Core hybrid property (informal, single-run check): flipping ONE
    source's secret must change the combined output. This guards against
    a naive combiner that accidentally ignores one input."""
    encapsulations, shared_secrets, ciphertexts = _make_hybrid_encapsulations()
    baseline = combine_from_secrets(shared_secrets, ciphertexts).root_key

    # corrupt only the classical secret
    tampered_secrets = list(shared_secrets)
    alg_id, secret = tampered_secrets[0]
    tampered_secret = bytes((secret[0] ^ 0xFF,)) + secret[1:]
    tampered_secrets[0] = (alg_id, tampered_secret)

    tampered = combine_from_secrets(tampered_secrets, ciphertexts).root_key
    assert tampered != baseline

    # corrupt only the PQC secret instead
    tampered_secrets2 = list(shared_secrets)
    alg_id2, secret2 = tampered_secrets2[1]
    tampered_secret2 = bytes((secret2[0] ^ 0xFF,)) + secret2[1:]
    tampered_secrets2[1] = (alg_id2, tampered_secret2)

    tampered2 = combine_from_secrets(tampered_secrets2, ciphertexts).root_key
    assert tampered2 != baseline
    assert tampered2 != tampered


def test_combiner_binds_ciphertexts_not_just_secrets():
    """Changing a ciphertext (with secrets held constant) must also change
    the output - this is what prevents cross-source confusion attacks."""
    encapsulations, shared_secrets, ciphertexts = _make_hybrid_encapsulations()
    baseline = combine_from_secrets(shared_secrets, ciphertexts).root_key

    tampered_cts = list(ciphertexts)
    alg_id, ct = tampered_cts[0]
    tampered_ct = bytes((ct[0] ^ 0xFF,)) + ct[1:]
    tampered_cts[0] = (alg_id, tampered_ct)

    tampered = combine_from_secrets(shared_secrets, tampered_cts).root_key
    assert tampered != baseline


def test_combine_from_secrets_rejects_mismatched_order():
    _, shared_secrets, ciphertexts = _make_hybrid_encapsulations()
    reordered_cts = list(reversed(ciphertexts))
    with pytest.raises(ValueError):
        combine_from_secrets(shared_secrets, reordered_cts)


def test_single_source_combine_is_deterministic_given_same_inputs():
    classical = ClassicalSource()
    pub, priv = classical.generate_keypair()
    enc = classical.encapsulate(pub)

    result1 = combine([("x25519", enc)])
    result2 = combine([("x25519", enc)])
    assert result1.root_key == result2.root_key
