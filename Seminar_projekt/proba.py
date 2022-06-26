import nacl.bindings as b
import binascii
bob_pk, bob_sk = b.crypto_kx_keypair()
alice_pk, alice_sk = b.crypto_kx_keypair()
print ("Bob public key: ",binascii.b2a_hex(bob_pk))
print ("Bob private key: ",binascii.b2a_hex(bob_sk))
print ("Alice public key: ",binascii.b2a_hex(alice_pk))
print ("Alice private key: ",binascii.b2a_hex(alice_sk))
bob_rx_key, bob_tx_key=b.crypto_kx_server_session_keys(bob_pk,bob_sk,alice_pk)
alice_rx_key, alice_tx_key=b.crypto_kx_client_session_keys(alice_pk,alice_sk,bob_pk)
print ("\nBob RX key: ",binascii.b2a_hex(bob_rx_key))
print ("Bob TX key: ",binascii.b2a_hex(bob_tx_key))
print ("Alice RX key: ",binascii.b2a_hex(alice_rx_key))
print ("Bob TX key: ",binascii.b2a_hex(alice_tx_key))
if (bob_rx_key == alice_tx_key): print ("\nBob's Rx key is same as Alice's Tx key")
if (alice_rx_key == bob_tx_key): print ("Alice's Rx key is same as Bob's Tx key")