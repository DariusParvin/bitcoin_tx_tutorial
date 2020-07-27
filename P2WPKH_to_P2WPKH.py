import argparse
import hashlib
import ecdsa
import sys

def dSHA256(data):
    hash_1 = hashlib.sha256(data).digest()
    hash_2 = hashlib.sha256(hash_1).digest()
    return hash_2

def hash160(s):
    '''sha256 followed by ripemd160'''
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()

def privkey_to_pubkey(privkey):
    signing_key = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()

    x_cor = bytes.fromhex(verifying_key.to_string().hex())[:32] # The first 32 bytes are the x coordinate
    y_cor = bytes.fromhex(verifying_key.to_string().hex())[32:] # The last 32 bytes are the y coordinate
    if int.from_bytes(y_cor, byteorder="big", signed=True) % 2 == 0: # We need to turn the y_cor into a number.
        public_key = bytes.fromhex("02" + x_cor.hex())
    else:
        public_key = bytes.fromhex("03" + x_cor.hex())
    return public_key

parser = argparse.ArgumentParser()

# calculate_txid flag for illustrative purposes
parser.add_argument("--calculate_txid", "-db", action='store_true', help="debug mode: print out all tx details")

parser.add_argument("--txid_str", help="txid of input as string")
parser.add_argument("--index", help="index of outpoint")
parser.add_argument("--input_amount_btc", help="amount of btc in")
parser.add_argument("--privkey",  help="private key of outpoint as hex string")
parser.add_argument("--output1_value_btc", help="btc to output")
parser.add_argument("--output1_pubkey", help="pubkey of output as hex string")
parser.add_argument("--output2_value_btc", help="btc to output")
parser.add_argument("--output2_pubkey", help="pubkey of output as hex string")

args = parser.parse_args()

# If no tx input arguments are provided, use hardcoded values to generate an example tx
if len(sys.argv) > 2:
    txID_str = args.txid_str
    tx_index = int(args.index)
    input_amount_sat = int(float(args.input_amount_btc) * 100000000)
    privkey = bytes.fromhex(args.privkey)
    input_pubkey = privkey_to_pubkey(privkey)
    output1_value_sat = int(float(args.output1_value_btc) * 100000000)
    output1_pubkey = bytes.fromhex(args.output1_pubkey)
    output2_value_sat = int(float(args.output2_value_btc) * 100000000)
    output2_pubkey = bytes.fromhex(args.output2_pubkey)
else:
    print("Using hard coded example values")
    txID_str = "1222222222222222222222222222222233333333333333333333333333333333"
    tx_index = 0
    input_amount_sat = int(float(2.0001) * 100000000)
    privkey = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")
    input_pubkey = privkey_to_pubkey(privkey)
    output1_value_sat = int(float(1.5) * 100000000)
    output1_pubkey = bytes.fromhex("02f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90")
    output2_value_sat = int(float(0.5) * 100000000)
    output2_pubkey = bytes.fromhex("02f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90")

# VERSION, MARKER, FLAG
version = bytes.fromhex("0200 0000")
marker = bytes.fromhex("00")
flag = bytes.fromhex("01")

# INPUTS
tx_in_count = bytes.fromhex("01")

# INPUT 1 (there's only one input in this example)
# Convert txid and index to little endian
txid = (bytes.fromhex(txID_str))[::-1]
index = tx_index.to_bytes(4, byteorder="little", signed=False)

# P2WPKH input has an empty scriptSig field. The signature goes in the witness.
scriptSig = bytes.fromhex("00") # length of scriptSig is 0

# use 0xffffffff unless you are using OP_CHECKSEQUENCEVERIFY or Locktime
sequence = bytes.fromhex("ffff ffff")

tx_in = (
    txid
    + index
    + scriptSig
    + sequence
)

# OUTPUTS
tx_out_count = bytes.fromhex("02")

# OUTPUT 1 
output1_value = output1_value_sat.to_bytes(8, byteorder="little", signed=True)
# P2WPKH scriptPubKey
output1_scriptPK = bytes.fromhex("0014") + hash160(output1_pubkey)

# OUTPUT 2
output2_value = output2_value_sat.to_bytes(8, byteorder="little", signed=True)
# P2WPKH scriptPubKey
output2_scriptPK = bytes.fromhex("0014") + hash160(output2_pubkey)


tx_out = (
    output1_value
    + (len(output1_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + output1_scriptPK
    + output2_value
    + (len(output2_scriptPK)).to_bytes(1, byteorder="little", signed=False)
    + output2_scriptPK
)

# LOCKTIME
locktime = bytes.fromhex("0000 0000")


##########################################
# Put together the tx digest preimage
hashPrevOuts = dSHA256(txid + index)
hashSequence = dSHA256(sequence)
locking_script = (
    bytes.fromhex("76 a9 14")
    + hash160(input_pubkey)
    + bytes.fromhex("88 ac")
)
scriptcode = (
    (len(locking_script)).to_bytes(1, byteorder="little", signed=False)
    + locking_script
)
input_amount = input_amount_sat.to_bytes(8, byteorder="little", signed=True)
hashOutputs = dSHA256(tx_out)
sighash = bytes.fromhex("0100 0000")

tx_digest_preimage = (
    version
    + hashPrevOuts
    + hashSequence
    + txid
    + index
    + scriptcode
    + input_amount
    + sequence
    + hashOutputs
    + locktime
    + sighash
)

tx_digest = dSHA256(tx_digest_preimage)

signing_key = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1) 
signature = signing_key.sign_digest(tx_digest, sigencode=ecdsa.util.sigencode_der_canonize)

witness = (
    # indicate the number of stack items for the txin
    # 2 items for signature and pubkey
    bytes.fromhex("02")

    # signature
    + (len(signature)+1).to_bytes(1, byteorder="little", signed=False)
    + signature
    + bytes.fromhex("01")  # sighash type flag

    # public key
    + (len(input_pubkey)).to_bytes(1, byteorder="little", signed=False)
    + input_pubkey
)

final_tx = (
    version
    + marker
    + flag
    + tx_in_count
    + tx_in
    + tx_out_count
    + tx_out
    + witness
    + locktime
)

print(final_tx.hex())

# calculate_txid flag is here for illustrative purposes. The txid is generated
# by hashing the legacy (pre-segwit) tx format.
if args.calculate_txid:
    # Convert to pre-segwit format (remove marker, flag, and witness)
    final_tx_legacy = (
        version
        + tx_in_count
        + tx_in
        + tx_out_count
        + tx_out
        + locktime
    )
    # Double sha256 and convert to little endian for txid
    new_txid = dSHA256(final_tx_legacy)[::-1]
    print("\ntxid: ",new_txid.hex())