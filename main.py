import os
import time
from flask import jsonify

from vrf import get_public_key, ecvrf_prove, ecvrf_proof_to_hash

SECRET_KEY = bytes.fromhex(os.getenv("SECRET_KEY"))
if len(SECRET_KEY) != 32:
    raise ValueError("Missing 32-byte HEX formatted SECRET_KEY env")
    
def vrf(request):
    data = request.get_json()
    available_time = int(data["timestamp"])
    seed = data["seed"]
    if available_time > int(time.time()):
        return jsonify({"error": "Too soon to reveal the random value"}), 400
    alpha_string = "{}:{}".format(seed, available_time).encode()
    pi_ok, pi_string = ecvrf_prove(SECRET_KEY, alpha_string)
    if pi_ok != "VALID":
        return jsonify({"error": "Error generating VRF proof"}), 500
    beta_ok, beta_string = ecvrf_proof_to_hash(pi_string)
    if beta_ok != "VALID":
        return jsonify({"error": "Error generating VRF hash"}), 500
    return jsonify({"proof": pi_string.hex(), "hash": beta_string.hex()})
