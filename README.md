Local Storage as dynamic app storage
-------------------------------------

We use the local storage alotted to a Smart Signature when it opts into our application to extend the storage space available to an application.

The Smart Signature may be a simple smart signature with two functions, create and destroy. 

A Template Smart Signature allows us to compute the address for a given subkey if we know the template variables.

The Address of a Smart Signature is `Sha512_256("Program"||bytecode)`.  


### Operations

#### Create

During the create operation, the account for the Smart Signature is seeded with enough algos to cover the minimum blanace.  Additionally an ApplicationOptInTransaction is atomically grouped to opt it's account into the Application.

#### Destroy

The Smart Signature is given the ability to approve an ApplicationCloseOut transaction and the Algos are closed back to the admin address. 


### Use

To compute the address of the Smart Signature, the bytecode of the populated contract must be determined. 

This can be done by using the `.teal` source file and string replacing the `TMPL_` variables with the ones you'd like, then compiling the populated Smart Signature.

It can also be done by using the `.teal.tok` assembly file and a mapping of the `TMPL_` byte positions and types. The assembled bytecode has the properly encoded bytes injected and the result should be a valid assembled file.



## This Example

This example is meant to allow a large sequence of numbers we've already seen. We use some logic to treat the available Local Storage as a large binary object. 

The template variable in the contract is a deterministic integer that we can use as an offset into the sequence of numbers. 

We store boolean true values as a bit flipped to 1. 

The amount of storage available per Smart Signature account is: 

```py
max_keys = 16 # 16 k/v pairs avail in local storage
max_bytes_per_key = 128 - 1 # 128 bytes max combined, but need space for a key
bits_per_byte = 8 

bits_per_key = max_bytes_per_key * bits_per_byte
max_bytes = max_bytes_per_key * max_keys
max_bits = bits_per_byte * max_bytes # 16256
```




