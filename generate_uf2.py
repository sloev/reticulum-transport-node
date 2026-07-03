import os
Import("env")

def generate_uf2(source, target, env):
    firmware_hex = str(source[0]).replace(".elf", ".hex")
    firmware_uf2 = str(source[0]).replace(".elf", ".uf2")

    # uf2conv.py ships inside the Adafruit nRF52 core package for this board.
    platform_dir = env.PioPlatform().get_package_dir("framework-arduinoadafruitnrf52-seeed")
    if not platform_dir:
        print("generate_uf2: framework-arduinoadafruitnrf52-seeed package not found, skipping UF2 generation")
        return
    uf2conv_path = os.path.join(platform_dir, "tools", "uf2conv", "uf2conv.py")

    # 0xADA52840 is the standard UF2 family ID for the Adafruit nRF52840 bootloader.
    cmd = " ".join([
        '"$PYTHONEXE"',
        f'"{uf2conv_path}"',
        '-c', '-f', '0xADA52840',
        f'"{firmware_hex}"',
        '-o', f'"{firmware_uf2}"'
    ])

    print(f"--- Generating UF2 at {firmware_uf2} ---")
    env.Execute(cmd)

env.AddPostAction("$BUILD_DIR/${PROGNAME}.hex", generate_uf2)
