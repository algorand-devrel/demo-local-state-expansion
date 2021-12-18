import base64
import json
from os import close
from algosdk.encoding import future_msgpack_decode, msgpack_encode
import uvarint

from pyteal import *

from algosdk import *
from algosdk.v2client import algod
from algosdk.future.transaction import *

from app import get_clear_src, get_approval_src
from sandbox import get_accounts


token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
url = "http://localhost:4001"

client = algod.AlgodClient(token, url)


class TmplSig:
    def __init__(self, tmpl_name="sig.tmpl.teal"):
        with open(tmpl_name + ".tok", "rb") as f:
            self.tmpl = list(f.read())

        with open(tmpl_name + ".map.json", "r") as f:
            self.map = json.loads(f.read())

        # Make sure they're sorted into the order they appear in
        # the contract or the `shift` will be wrong
        self.tmpl_vars = dict(
            sorted(
                self.map["template_variables"].items(),
                key=lambda item: item[1]["position"],
            )
        )

    def populate(self, vars) -> LogicSigAccount:
        contract = self.tmpl[:]
        shift = 0

        for k, v in self.tmpl_vars.items():
            if k not in vars:
                raise KeyError("Missing key: {}".format(k))

            pos = v["position"] + shift
            if v["type"] == 1:  # bytes
                # Get the value we're about to encode
                val = bytes.fromhex(vars[k])

                # Encode the length as uvarint
                lbyte = uvarint.encode(len(val))

                # -1 to account for the existing 00 byte for length
                shift += (len(lbyte) - 1) + len(val)

                # +1 to overwrite the existing 00 byte for length
                contract[pos : pos + 1] = lbyte + val

            else:  # int
                val = uvarint.encode(vars[k])

                # -1 to account for existing 00 byte
                shift += len(val) - 1

                # +1 to overwrite existing 00 byte
                contract[pos : pos + 1] = val

        # If you want to inspect the output,
        # uncomment this, then `goal clerk compile -D tmp.teal.tok`
        # and verify its populated the template variables correctly
        # with open("tmp.teal.tok", "wb") as f:
        #   f.write(bytes(contract))

        return LogicSigAccount(bytes(contract))


app_id = 10
seed_amt = int(1e9)

max_keys = 16
max_bytes_per_key = 127
bits_per_byte = 8

bits_per_key = max_bytes_per_key * bits_per_byte
max_bytes = max_bytes_per_key * max_keys
max_bits = bits_per_byte * max_bytes


def get_addr_idx(seq_id):
    return int(seq_id / max_bits)


def get_byte_idx(seq_id):
    return int(seq_id/bits_per_byte) % max_bytes

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


def demo(app_id=None):

    tsig = TmplSig()

    # Get Account from sandbox
    addr, sk = get_accounts()[0]
    print("Using {}".format(addr))

    # Create app if needed
    if app_id is None:
        app_id = create_app(addr, sk)
        print("Created app: {}".format(app_id))
    else:
        update_app(app_id, addr, sk)
        print("Updated app: {}".format(app_id))

    seq_id = 1000000003 
    #debug_seq(seq_id)

    lsa = tsig.populate({"TMPL_ADDR_IDX": get_addr_idx(seq_id)})
    print("For seq {} address is {}".format(seq_id, lsa.address()))

    if not account_exists(app_id, lsa.address()):
        # Create it
        sp = client.suggested_params()

        seed_txn = PaymentTxn(addr, sp, lsa.address(), seed_amt)
        optin_txn = ApplicationOptInTxn(lsa.address(), sp, app_id)

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
            accounts=[lsa.address()],
        )
        signed_flip = flip_txn.sign(sk)
        result = send("flip_bit", [signed_flip])
        if 'logs' in result:
            print(result['logs'])

        bits = check_bits_set(app_id, get_start_bit(seq_id), lsa.address())
        print(bits)
    except Exception as e:
        print("failed to flip bit :( {}".format(e))

    if False:
        # destroy it
        sp = client.suggested_params()

        closeout_txn = ApplicationCloseOutTxn(lsa.address(), sp, app_id)
        close_txn = PaymentTxn(lsa.address(), sp, addr, 0, close_remainder_to=addr)

        assign_group_id([closeout_txn, close_txn])

        signed_closeout = LogicSigTransaction(closeout_txn, lsa)
        signed_close = LogicSigTransaction(close_txn, lsa)

        send("destroy", [signed_closeout, signed_close])


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

            bits = list(format(val, 'b').zfill(8))
            bits.reverse()
            for bit_idx, bit in enumerate(bits):
                if bit == '0':
                    continue

                byte_start = byte_idx + key*max_bytes_per_key

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


if __name__ == "__main__":
    demo(1)
