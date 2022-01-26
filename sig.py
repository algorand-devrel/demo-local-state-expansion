from pyteal import *


def sig_tmpl():

    # We encode the app id as an 8 byte integer to ensure its a known size
    # Otherwise the uvarint encoding may produce a different byte offset
    # for the template variables
    admin_app_id = Tmpl.Int("TMPL_APP_ID")
    seed_amt = Tmpl.Int("TMPL_SEED_AMT")

    @Subroutine(TealType.uint64)
    def init():
        algo_seed = Gtxn[0]
        optin = Gtxn[1]

        return And(
            Global.group_size() == Int(2),
            algo_seed.type_enum() == TxnType.Payment,
            algo_seed.amount() == seed_amt,
            algo_seed.rekey_to() == Global.zero_address(),
            algo_seed.close_remainder_to() == Global.zero_address(),
            optin.type_enum() == TxnType.ApplicationCall,
            optin.on_completion() == OnComplete.OptIn,
            optin.application_id() == admin_app_id,
            optin.rekey_to() == Global.zero_address(),
        )

    return Seq(
        # Just putting adding this as a tmpl var to make the address unique and deterministic
        # We don't actually care what the value is, pop it
        Pop(Tmpl.Int("TMPL_ADDR_IDX")),
        Pop(Tmpl.Bytes("TMPL_EMITTER_ID")),
        init(),
    )


def get_sig_tmpl(**kwargs):
    return compileTeal(
        sig_tmpl(**kwargs), mode=Mode.Signature, version=5, assembleConstants=True
    )


if __name__ == "__main__":
    with open("sig.tmpl.teal", "w") as f:
        f.write(get_sig_tmpl())
