import base64
import random

from algosdk.v2client import algod
from algosdk.encoding import msgpack_encode
from algosdk.future.transaction import *

from sandbox import get_accounts

from app import get_clear_src, get_approval_src
from sig import get_sig_tmpl

token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
url = "http://localhost:4001"

client = algod.AlgodClient(token, url)

# To delete accounts in seq loop
cleanup = False

app_id = 1  # Your app id
seed_amt = int(1e9)  # How much to give the acct
admin_addr = "PU2IEPAQDH5CCFWVRB3B5RU7APETCMF24574NA5PKMYSHM2ZZ3N3AIHJUI"  # Address used to admin

max_keys = 16
max_bytes_per_key = 127
bits_per_byte = 8

bits_per_key = max_bytes_per_key * bits_per_byte
max_bytes = max_bytes_per_key * max_keys
max_bits = bits_per_byte * max_bytes


# TmplSig is a class to hold the source of a template contract
# populate can be called to get a LogicSig with the variables replaced
class TmplSig:

    def __init__(self):
        # Get compiled sig
        self.tmpl = get_sig_tmpl(
            app_id=app_id, seed_amt=seed_amt, admin_addr=admin_addr
        )

    # Just string replace the var in the contract and recompile
    # This can be done with a compiled contract but we're lazy in
    # this demo
    def populate(self, vars):
        src = self.tmpl
        for k, v in vars.items():
            src = src.replace(k, str(v))
        res = client.compile(src)

        return LogicSigAccount(base64.b64decode(res["result"]))


def demo():
    global app_id

    # Get Account from sandbox
    addr, sk = get_accounts()[0]
    print("Using {}".format(addr))

    # Create app if needed
    if app_id is None:
        app_id = create_app(addr, sk)
        print("Created app: {}".format(app_id))
    else:
        # No need for this when you're not debugging
        update_app(app_id, addr, sk)
        print("Updated app: {}".format(app_id))

    # Instantiate once, has ref to sig
    tsig = TmplSig()

    # Lazy cache accts we see
    cache = {}

    # Get some random sequence
    seq = [random.randint(0, int(1e6)) for x in range(int(1e3))]

    for seq_id in seq:
        lsa = tsig.populate({"TMPL_ADDR_IDX": get_addr_idx(seq_id)})

        print("For seq {} address is {}".format(seq_id, lsa.address()))

        sig_addr = lsa.address()

        if sig_addr not in cache and not account_exists(app_id, sig_addr):
            # Create it
            sp = client.suggested_params()

            seed_txn = PaymentTxn(addr, sp, sig_addr, seed_amt)
            optin_txn = ApplicationOptInTxn(sig_addr, sp, app_id)

            assign_group_id([seed_txn, optin_txn])

            signed_seed = seed_txn.sign(sk)
            signed_optin = LogicSigTransaction(optin_txn, lsa)

            send("create", [signed_seed, signed_optin])

        try:
            # Flip the bit
            sp = client.suggested_params()
            flip_txn = ApplicationNoOpTxn(
                addr,
                sp,
                app_id,
                ["flip_bit", seq_id.to_bytes(8, "big")],
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


def update_app(id, addr, sk):
    # Read in approval teal source && compile
    app_result = client.compile(get_approval_src())
    app_bytes = base64.b64decode(app_result["result"])

    # Read in clear teal source && compile
    clear_result = client.compile(get_clear_src())
    clear_bytes = base64.b64decode(clear_result["result"])

    # Get suggested params from network
    sp = client.suggested_params()
    # Create the transaction
    update_txn = ApplicationUpdateTxn(addr, sp, id, app_bytes, clear_bytes)

    # Sign it
    signed_txn = update_txn.sign(sk)

    # Ship it
    txid = client.send_transaction(signed_txn)

    # Wait for the result so we can return the app id
    return wait_for_confirmation(client, txid, 4)


def create_app(addr, sk):
    # Read in approval teal source && compile
    app_result = client.compile(get_approval_src())
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
