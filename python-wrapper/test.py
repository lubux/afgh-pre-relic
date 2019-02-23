import pre

alice = pre.generate_key()
print("Alice key:\n%s\n" % alice.hex()[:16])
bob = pre.generate_key()
print("Bob key:\n%s\n" % bob.hex()[:16])
token = pre.generate_token(alice, bob)
print("token:\n%s\n" % token.hex()[:16])

msg1 = pre.generate_msg()
print("msg1:\n%s\n" % msg1.hex()[:16])
ints1 = pre.msg_to_ints(msg1)
print("ints1:\n%s\n" % ints1)

cipher = pre.encrypt(alice, msg1)
print("cipher:\n%s\n" % cipher.hex()[:16])

msg2 = pre.decrypt(alice, cipher)
print("msg2:\n%s\n" % msg2.hex()[:16])
ints2 = pre.msg_to_ints(msg2)
print("ints2:\n%s\n" % ints2)

re_cipher = pre.apply_token(token, msg)
print("re_cipher:\n%s\n" % re_cipher.hex()[:16])

msg3 = pre.decrypt(bob, cipher)
print("msg3:\n%s\n" % msg3.hex()[:16])
ints3 = pre.msg_to_ints(msg3)
print("ints3:\n%s\n" % ints3)

assert ints1 == ints2 == ints3
