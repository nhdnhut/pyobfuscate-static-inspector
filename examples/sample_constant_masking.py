"""Harmless fixture: Arithmetic constant masking, reversed string, chr/ord join."""

# Obfuscated with arithmetic & bitwise constants
port = ((0x10 ^ 0x24) + 12 * 5) << 2
timeout = (100 * 2 - 50) // 3

# String concealed via slicing and dynamic join
greeting = 'dlroW olleH'[::-1]
secret_marker = ''.join([chr(c ^ 0x1F) for c in [126, 114, 110, 110, 120]])

if True:
    print(f"Status: {greeting}, Port: {port}, Timeout: {timeout}, Marker: {secret_marker}")
else:
    print("This dead branch will be safely pruned")
