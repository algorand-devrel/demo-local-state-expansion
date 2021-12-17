from pyteal import *

admin_addr = Bytes("0xdeadbeef")
admin_app_id = Int(1)
seed_amt = Int(int(1e9))

def sig_tmpl():
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
        closeout  = Gtxn[0] 

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
        Pop(Tmpl.Int("TMPL_ADDR_IDX")),
        Cond(
            [Global.group_size() != Int(2), Reject()],
            [Arg(1) == Bytes("init"), Return(init())],
            [Arg(1) == Bytes("close"), Return(close())]
        ),
    )

if __name__ == "__main__":
    with open("sig.tmpl.teal", "w") as f:
        f.write(compileTeal(sig_tmpl(), mode=Mode.Signature, version=5, assembleConstants=True))
