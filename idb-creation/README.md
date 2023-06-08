# Creating the IDB file for analysis.

Follow the steps below for .idb creation.

The .idb file will be used for function identification.

## Steps
1. Run `parse_modem.py` and give the modem file path.
2. Load the binary with `main` in the name among the created binaries into IDA Pro. (MANUAL)
    - Select ARM as the archtecture.
    - Select "Manual Load"
        - Set the `ROM start address` and `Loading address` as the starting address written in the binary's name.
        - ex. 0x40010000
3. Load `analyze.py`
