from pyteal import *
from pytealutils import *
import os

# Maximum number of bytes for a blob
max_bytes = 127 * 16
max_bits = max_bytes * 8

action_lookup = Bytes("lookup")
action_flip_bit = Bytes("flip_bit")

admin_addr = Addr("PU2IEPAQDH5CCFWVRB3B5RU7APETCMF24574NA5PKMYSHM2ZZ3N3AIHJUI")
seed_amt = Int(int(1e9))


def approval():

    blob = Blob()

    # The bit index (seq) should always be the second arg
    bit_idx = Btoi(Txn.application_args[1])

    # Offset into the blob of the byte
    byte_offset = bit_idx % Int(max_bytes)

    # Offset into the byte of the bit
    bit_offset = bit_idx % Int(max_bits)

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
        return GetBit(blob.read(Int(1), byte_offset, Int(1)), bit_offset%Int(8))

    @Subroutine(TealType.uint64)
    def flip_bit():
        b = ScratchVar()
        bit_byte_offet = bit_idx % Int(8)
        return Seq(
            b.store(Btoi(blob.read(Int(1), byte_offset, Int(1)))),
            #blob.write(Int(1), byte_offset, Bytes("asdfadsfasasdfasdfasdfasdfdf")),
            blob.write(
                Int(1), # Passed address
                byte_offset,
                Itob(SetBit(
                    b.load(),
                    bit_byte_offet,
                    GetBit(BitwiseNot(b.load()), bit_byte_offet),
                )),
            )
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

def get_approval_src():
    return compileTeal(approval(), mode=Mode.Application, version=5, assembleConstants=True)

def get_clear_src():
    return compileTeal(clear(), mode=Mode.Application, version=5, assembleConstants=True)

if __name__ == "__main__":
    path = os.path.dirname(os.path.abspath(__file__))

    with open(os.path.join(path, "approval.teal"), "w") as f:
        f.write(get_approval_src())

    with open(os.path.join(path, "clear.teal"), "w") as f:
        f.write(get_clear_src())
