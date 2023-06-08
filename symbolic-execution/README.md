# Symbolic execution

This directory performs symbolic execution on the baseband firmware with angr and analyzes the result to see if there are any discrepancies.

## analyze_base.py

`analyze_base.py` is the only file you need to run.
The results will be in the `results` folder of this directory.
The program requires a firmware and 2 configuration files; one for the vendor and another for the firmware.
If to run a firmware from a vendor not already defined, an additional vendor specific analysis file is needed.
More specific details can be found underneath.

Specify the name of the target fimrware and the configuration files with the options.

## Vendor Configuration File

The vendor configuration file requires the following information.
```
  :analysis:              Path to vendor specific analysis file.
  :arch:                  Architecture of vendor.
  :base_addr:             Base address of vendor.
  :dest_addr:             End address to reach in symbolic execution, if not needed set as -1.
  :unconstrained:         Whether to use unconstrained symbolic execution.
  :additional:            Name of additional arguments needed depending on the vendor specific analysis file.
```
For examples, look into the `config_vendor.yaml` file.

## Firmware Configuration File

The firmware configuration file requires the following information.
```
  :target:                Path to target firmware.
  :vendor:                Vendor name.
  :integrity_func:        Address of the target integrity protection function.
  :mac_validation_func:   Address of the MAC validating function.                 
  :skip_funcs:            Functions that can be skipped to avoid path explosion. (Irrelevant to functionality.)

  Additional arguments.
```
The `vendor` argument should be the name in the vendor configuration file.
For examples, look into the `config_vendor.yaml` file.

## Vendor Specific Analysis

The vendor specific analysis file should have the following 3 functions.

### symbolize_vendor()
This functions registers symbolic variables of the message buffer and the security state depending on how they are implemented in the firmware.

### add_hook_vendor()
This function adds hooks to functions that has to return a value rather than 0.
Use the `create_hook` function in the `utils.py` file.

### acceptable()
This function defines what states should be considered as one that passed the integrity protection function.

## Functions to hook

To avoid path explosion while symbolic execution, functions that are irrelevant to the integrity protection should be skipped.
The functions under `skip_funcs` in the firmware configuration file will be hooked to return 0.
An example for functions to be hooked would be those related to logging.