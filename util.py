from pyteal import *


@Subroutine(TealType.bytes)
def encode_uvarint(val: TealType.uint64, b: TealType.bytes):
    buff = ScratchVar()
    return Seq(
        buff.store(b),
        Concat(
            buff.load(),
            If(
                val >= Int(128),
                encode_uvarint(
                    val >> Int(7),
                    Extract(Itob((val & Int(255)) | Int(128)), Int(7), Int(1)),
                ),
                Extract(Itob(val & Int(255)), Int(7), Int(1)),
            ),
        ),
    )
