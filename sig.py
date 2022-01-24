from pyteal import *


def sig_tmpl(
    admin_addr="CXDSSP2ZN2BLXG2P2FZ7YQNSBH7LX4723RJ6PW7IETSIO2UZE5GMIBZXXI",
    seed_amt=int(1e9),
):
    admin_addr = Addr(admin_addr)
    seed_amt = Int(seed_amt)

    # We encode the app id as an 8 byte integer to ensure its a known size
    # Otherwise the uvarint encoding may produce a different byte offset
    # for the template variables
    admin_app_id = Btoi(Tmpl.Bytes("TMPL_APP_ID"))

    @Subroutine(TealType.uint64)
    def init():
        algo_seed = Gtxn[0]
        optin = Gtxn[1]

        return And(
            algo_seed.type_enum() == TxnType.Payment,
            algo_seed.sender() == admin_addr,
            algo_seed.amount() == seed_amt,
            optin.type_enum() == TxnType.ApplicationCall,
            optin.on_completion() == OnComplete.OptIn,
            optin.application_id() == admin_app_id,
        )

    @Subroutine(TealType.uint64)
    def close():
        closeout = Gtxn[0]
        algo_close = Gtxn[1]
        return And(
            closeout.type_enum() == TxnType.ApplicationCall,
            closeout.on_completion() == OnComplete.CloseOut,
            closeout.application_id() == admin_app_id,
            algo_close.type_enum() == TxnType.Payment,
            algo_close.receiver() == admin_addr,
            algo_close.close_remainder_to() == admin_addr,
            algo_close.sender() == admin_addr,
            algo_close.amount() == Int(int(0)),
        )

    return Seq(
        # Just putting adding this as a tmpl var to make the address unique and deterministic
        # We don't actually care what the value is, pop it
        Pop(Tmpl.Int("TMPL_ADDR_IDX")),
        Pop(Tmpl.Bytes("TMPL_EMITTER_ID")),
        Cond(
            [Global.group_size() != Int(2), Reject()],
            [Int(1), Return(Or(init(), close()))],
        ),
    )


def get_sig_tmpl(**kwargs):
    return compileTeal(
        sig_tmpl(**kwargs), mode=Mode.Signature, version=5, assembleConstants=True
    )


if __name__ == "__main__":
    with open("sig.tmpl.teal", "w") as f:
        f.write(get_sig_tmpl())
