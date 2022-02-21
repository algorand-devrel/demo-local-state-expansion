import json
import base64
import uvarint
import os

from typing import Dict, Union

from pyteal import *
from algosdk.future.transaction import LogicSigAccount
from pytealutils.storage import LocalBlob
from pytealutils.strings import encode_uvarint

# Maximum number of bytes for a blob
max_bytes = 127 * 16
max_bits = max_bytes * 8

action_lookup = Bytes("lookup")
action_flip_bit = Bytes("flip_bit")


class TmplSig:
    """KeySig class reads in a json map containing assembly details of a template smart signature and allows you to populate it with the variables
    In this case we are only interested in a single variable, the key which is a byte string to make the address unique.
    In this demo we're using random strings but in practice you can choose something meaningful to your application
    """

    def __init__(self, name):
        # Read the source map
        with open("{}.json".format(name)) as f:
            self.map = json.loads(f.read())

        self.src = base64.b64decode(self.map["bytecode"])
        self.sorted = dict(
            sorted(
                self.map["template_labels"].items(),
                key=lambda item: item[1]["position"],
            )
        )

    def populate(self, values: Dict[str, Union[str, int]]) -> LogicSigAccount:
        """populate uses the map to fill in the variable of the bytecode and returns a logic sig with the populated bytecode"""
        # Get the template source
        contract = list(base64.b64decode(self.map["bytecode"]))

        shift = 0
        for k, v in self.sorted.items():
            if k in values:
                pos = v["position"] + shift
                if v["bytes"]:
                    val = bytes.fromhex(values[k])
                    lbyte = uvarint.encode(len(val))
                    # -1 to account for the existing 00 byte for length
                    shift += (len(lbyte) - 1) + len(val)
                    # +1 to overwrite the existing 00 byte for length
                    contract[pos : pos + 1] = lbyte + val
                else:
                    val = uvarint.encode(values[k])
                    # -1 to account for existing 00 byte
                    shift += len(val) - 1
                    # +1 to overwrite existing 00 byte
                    contract[pos : pos + 1] = val

        # Create a new LogicSigAccount given the populated bytecode
        return LogicSigAccount(bytes(contract))

    def get_bytecode_chunk(self, idx: int) -> Bytes:
        start = 0
        if idx > 0:
            start = list(self.sorted.values())[idx - 1]["position"] + 1

        stop = len(self.src)
        if idx < len(self.sorted):
            stop = list(self.sorted.values())[idx]["position"]

        chunk = self.src[start:stop]
        return Bytes(chunk)


def approval(
    admin_addr: str = "",
    seed_amt: int = 0,
    tmpl_sig: TmplSig = None,
):

    seed_amt = Int(seed_amt)
    admin_addr = Addr(admin_addr)

    blob = LocalBlob()

    # The bit index (seq) should always be the second arg
    bit_idx = Btoi(Txn.application_args[1])

    # Offset into the blob of the byte
    byte_offset = (bit_idx / Int(8)) % Int(max_bytes)

    # Offset into the byte of the bit
    bit_offset = bit_idx % Int(max_bits)

    # start index of seq ids an account is holding
    acct_seq_start = bit_idx / Int(max_bits)

    @Subroutine(TealType.bytes)
    def get_sig_address(acct_seq_start: Expr, emitter: Expr):
        # We could iterate over N items and encode them for a more general interface
        # but we inline them directly here

        return Sha512_256(
            Concat(
                Bytes("Program"),
                # ADDR_IDX aka sequence start
                tmpl_sig.get_bytecode_chunk(0),
                encode_uvarint(acct_seq_start, Bytes("")),
                # EMMITTER_ID
                tmpl_sig.get_bytecode_chunk(1),
                encode_uvarint(Len(emitter), Bytes("")),
                emitter,
                # SEED_AMT
                tmpl_sig.get_bytecode_chunk(2),
                encode_uvarint(seed_amt, Bytes("")),
                # APP_ID
                tmpl_sig.get_bytecode_chunk(3),
                encode_uvarint(Global.current_application_id(), Bytes("")),
                # TMPL_APP_ADDRESS
                tmpl_sig.get_bytecode_chunk(4),
                encode_uvarint(Len(Global.current_application_address()), Bytes("")),
                Global.current_application_address(),
                tmpl_sig.get_bytecode_chunk(5),
            )
        )

    @Subroutine(TealType.uint64)
    def optin():
        # Alias for readability
        algo_seed = Gtxn[0]
        optin = Gtxn[1]

        well_formed_optin = And(
            # Check that we're paying it
            algo_seed.type_enum() == TxnType.Payment,
            algo_seed.sender() == admin_addr,
            algo_seed.amount() == seed_amt,
            # Check that its an opt in to us
            optin.type_enum() == TxnType.ApplicationCall,
            optin.on_completion() == OnComplete.OptIn,
            # Not strictly necessary since we wouldn't be seeing this unless it was us, but...
            optin.application_id() == Global.current_application_id(),
        )

        return Seq(
            # Make sure its a valid optin
            Assert(well_formed_optin),
            # Init by writing to the full space available for the sender (Int(0))
            blob.zero(Int(0)),
            # we gucci
            Int(1),
        )

    @Subroutine(TealType.uint64)
    def lookup():
        return GetBit(blob.get_byte(Int(1), byte_offset), bit_offset % Int(8))

    @Subroutine(TealType.uint64)
    def flip_bit():
        b = ScratchVar()
        bit_byte_offset = bit_idx % Int(8)
        return Seq(
            Assert(
                Txn.accounts[1]
                == get_sig_address(acct_seq_start, Txn.application_args[2])
            ),
            b.store(blob.get_byte(Int(1), byte_offset)),
            blob.set_byte(
                Int(1),
                byte_offset,
                SetBit(
                    b.load(),
                    bit_byte_offset,
                    GetBit(BitwiseNot(b.load()), bit_byte_offset),
                ),
            ),
            Int(1),
        )

    router = Cond(
        [Txn.application_args[0] == action_flip_bit, flip_bit()],
        [Txn.application_args[0] == action_lookup, lookup()],
    )

    return Cond(
        [Txn.application_id() == Int(0), Int(1)],
        [Txn.on_completion() == OnComplete.DeleteApplication, Int(0)],
        [Txn.on_completion() == OnComplete.UpdateApplication, Int(1)],
        [Txn.on_completion() == OnComplete.CloseOut, Int(1)],
        [Txn.on_completion() == OnComplete.OptIn, optin()],
        [Txn.on_completion() == OnComplete.NoOp, router],
    )


def clear():
    return Return(Int(1))


def get_approval_src(**kwargs):
    return compileTeal(
        approval(**kwargs), mode=Mode.Application, version=6, assembleConstants=True
    )


def get_clear_src():
    return compileTeal(
        clear(), mode=Mode.Application, version=6, assembleConstants=True
    )


if __name__ == "__main__":
    path = os.path.dirname(os.path.abspath(__file__))

    with open(os.path.join(path, "approval.teal"), "w") as f:
        f.write(get_approval_src())

    with open(os.path.join(path, "clear.teal"), "w") as f:
        f.write(get_clear_src())
