import base64
import random
import json
import uvarint

from typing import Tuple, Dict
from algosdk.v2client import algod
from algosdk.encoding import msgpack_encode
from algosdk.encoding import decode_address, encode_address
from algosdk.logic import get_application_address
from algosdk.future.transaction import *

from dryrun import DryrunResponse
from sandbox import get_accounts

from app import get_clear_src, get_approval_src, TmplSig

token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
url = "http://localhost:4001"

client = algod.AlgodClient(token, url)

# To delete accounts in seq loop
cleanup = False

app_id = None
admin_addr = "CXDSSP2ZN2BLXG2P2FZ7YQNSBH7LX4723RJ6PW7IETSIO2UZE5GMIBZXXI"
seed_amt = int(1e9)

max_keys = 16
max_bytes_per_key = 127
bits_per_byte = 8

bits_per_key = max_bytes_per_key * bits_per_byte
max_bytes = max_bytes_per_key * max_keys
max_bits = bits_per_byte * max_bytes


# TmplSig is a class to hold the source of a template contract
# populate can be called to get a LogicSig with the variables replaced


def demo():
    global app_id

    # Get Account from sandbox
    addr, sk = get_accounts()[0]
    print("Using {}".format(addr))

    # reads from sig.json
    tsig = TmplSig("sig")

    # Create app if needed
    if app_id is None:
        print("Creating app")
        app_id = create_app(addr, sk, seed_amt, tsig)
        print("Created app: {}".format(app_id))

    # Lazy cache accts we see
    cache = {}

    # Get some random sequence
    seq = [random.randint(0, int(1e3)) for x in range(1000)]
    emitter_id = "deadbeef" * 4

    aa = decode_address(get_application_address(app_id)).hex()

    for seq_id in seq:

        lsa = tsig.populate(
            {
                "TMPL_SEED_AMT": seed_amt,
                "TMPL_APP_ID": app_id,
                "TMPL_ADDR_IDX": get_addr_idx(seq_id),
                "TMPL_APP_ADDRESS": aa,
                "TMPL_EMITTER_ID": emitter_id,
            }
        )

        # with open("sig.bin", "wb") as f:
        #    f.write(lsa.lsig.logic)

        print("For seq {} address is {}".format(seq_id, lsa.address()))

        sig_addr = lsa.address()

        if sig_addr not in cache and not account_exists(app_id, sig_addr):
            # Create it
            sp = client.suggested_params()

            seed_txn = PaymentTxn(addr, sp, sig_addr, seed_amt)
            optin_txn = ApplicationOptInTxn(sig_addr, sp, app_id)
            rekey_txn = PaymentTxn(sender=sig_addr, sp=sp, receiver=sig_addr, amt=0, rekey_to=get_application_address(app_id))

            assign_group_id([seed_txn, optin_txn, rekey_txn])

            signed_seed = seed_txn.sign(sk)
            signed_optin = LogicSigTransaction(optin_txn, lsa)
            signed_rekey = LogicSigTransaction(rekey_txn, lsa)

            send("create", [signed_seed, signed_optin, signed_rekey])
        try:
            # Flip the bit
            sp = client.suggested_params()
            flip_txn = ApplicationNoOpTxn(
                addr,
                sp,
                app_id,
                ["flip_bit", seq_id.to_bytes(8, "big"), bytes.fromhex(emitter_id)],
                accounts=[sig_addr],
            )
            signed_flip = flip_txn.sign(sk)
            result = send("flip_bit", [signed_flip])

            if "logs" in result:
                print(result["logs"])

            bits = check_bits_set(app_id, get_start_bit(seq_id), sig_addr)
            cache[sig_addr] = bits

            print(
                "Accounts: {}, Bits Flipped: {}".format(
                    len(cache), sum([len(v) for _, v in cache.items()])
                )
            )
        except Exception as e:
            print("failed to flip bit :( {}".format(e.with_traceback()))

        if cleanup:
            # destroy it
            sp = client.suggested_params()

            closeout_txn = ApplicationCloseOutTxn(sig_addr, sp, app_id)
            close_txn = PaymentTxn(sig_addr, sp, addr, 0, close_remainder_to=addr)

            assign_group_id([closeout_txn, close_txn])

            signed_closeout = LogicSigTransaction(closeout_txn, lsa)
            signed_close = LogicSigTransaction(close_txn, lsa)

            send("destroy", [signed_closeout, signed_close])
            del cache[sig_addr]


# We're calling out tot he chain here, but in practice you'd be able to store
# the already created accounts in some local cache
def account_exists(app_id, addr):

    try:
        ai = client.account_info(addr)
        if "apps-local-state" not in ai:
            return False

        for app in ai["apps-local-state"]:
            if app["id"] == app_id:
                return True
    except:
        print("Failed to find account {}".format(addr))

    return False


def check_bits_set(app_id, start, addr):
    bits_set = {}

    ai = client.account_info(addr)
    for app in ai["apps-local-state"]:
        if app["id"] == app_id:
            app_state = app["key-value"]

    for kv in app_state:
        key = list(base64.b64decode(kv["key"]))[0]
        v = list(base64.b64decode(kv["value"]["bytes"]))

        for byte_idx, val in enumerate(v):
            if val == 0:
                continue

            bits = list(format(val, "b").zfill(8))
            bits.reverse()
            for bit_idx, bit in enumerate(bits):
                if bit == "0":
                    continue

                byte_start = byte_idx + key * max_bytes_per_key

                seq = start + byte_start * bits_per_byte + bit_idx

                bits_set[seq] = True

    return bits_set


def create_app(addr, sk, seed_amt, tmpl):
    # Read in approval teal source && compile
    app_result = client.compile(
        get_approval_src(admin_addr=addr, seed_amt=seed_amt, tmpl_sig=tmpl)
    )
    app_bytes = base64.b64decode(app_result["result"])

    # Read in clear teal source && compile
    clear_result = client.compile(get_clear_src())
    clear_bytes = base64.b64decode(clear_result["result"])

    gschema = StateSchema(0, 0)
    lschema = StateSchema(0, 16)

    # Get suggested params from network
    sp = client.suggested_params()
    # Create the transaction
    create_txn = ApplicationCreateTxn(
        addr, sp, 0, app_bytes, clear_bytes, gschema, lschema
    )

    # Sign it
    signed_txn = create_txn.sign(sk)

    # Ship it
    txid = client.send_transaction(signed_txn)

    # Wait for the result so we can return the app id
    result = wait_for_confirmation(client, txid, 4)

    return result["application-index"]


def send(name, signed_group, debug=False):
    print("Sending Transaction for {}".format(name))

    if debug:
        # drr = DryrunResponse(client.dryrun(create_dryrun(client, signed_group)))
        # print(drr.txns[0].app_trace())
        with open(name + ".msgp", "wb") as f:
            f.write(
                base64.b64decode(msgpack_encode(create_dryrun(client, signed_group)))
            )
        with open(name + ".txns", "wb") as f:
            for tx in signed_group:
                f.write(base64.b64decode(msgpack_encode(tx)))

    txid = client.send_transactions(signed_group)
    return wait_for_confirmation(client, txid, 4)


# Sanity checks
def get_addr_idx(seq_id):
    return int(seq_id / max_bits)


def get_byte_idx(seq_id):
    return int(seq_id / bits_per_byte) % max_bytes


def get_byte_key(seq_id):
    return int(get_byte_idx(seq_id) / max_bytes_per_key)


def get_bit_idx(seq_id):
    return int(seq_id % max_bits)


def get_start_bit(seq_id):
    return int(seq_id / max_bits) * max_bits


def debug_seq(s):
    print("for seq id: {}".format(s))
    print("\taddr idx: {}".format(get_addr_idx(s)))
    print("\tStart Bit: {}".format(get_start_bit(s)))
    print("\tbyte key: {}".format(get_byte_key(s)))
    print("\tbyte offset: {}".format(get_byte_idx(s)))
    print("\tbit offset: {}".format(get_bit_idx(s)))


if __name__ == "__main__":
    demo()
