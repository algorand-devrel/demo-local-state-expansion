from pyteal import *


def sig_tmpl(
    admin_addr="PU2IEPAQDH5CCFWVRB3B5RU7APETCMF24574NA5PKMYSHM2ZZ3N3AIHJUI",
    admin_app_id=1,
    seed_amt=int(1e9),
):
    admin_addr = Addr(admin_addr)
    admin_app_id = Int(admin_app_id)
    seed_amt = Int(seed_amt)

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
        algo_close = Gtxn[1]
        closeout = Gtxn[0]

        # TODO: actually check that we cosigned this transaction
        return And(
            algo_close.type_enum() == TxnType.Payment,
            algo_close.receiver() == admin_addr,
            algo_close.close_remainder_to() == admin_addr,
            algo_close.amount() == Int(int(0)),
            closeout.type_enum() == TxnType.ApplicationCall,
            closeout.on_completion() == OnComplete.CloseOut,
            closeout.application_id() == admin_app_id,
        )

    return Seq(
        # Just putting adding this as a tmpl var to make the address unique and deterministic
        # We don't actually care what the value is, pop it
        Pop(Tmpl.Int("TMPL_ADDR_IDX")),
        Cond(
            [Global.group_size() != Int(2), Reject()],
            [Int(1), Return(Or(init(), close()))],
        ),
    )


if __name__ == "__main__":
    with open("sig.tmpl.teal", "w") as f:
        f.write(
            compileTeal(
                sig_tmpl(), mode=Mode.Signature, version=5, assembleConstants=True
            )
        )
