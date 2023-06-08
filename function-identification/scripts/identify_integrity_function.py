import os
import logging
import time

import idc

from call_distance import CallDistance
from analyses import MACAnalysis, MsgTypeAnalysis, IntegrityFunctionAnalysis

MAXCALLDISTANCE = 10
l = logging.getLogger(__name__)
l.setLevel(logging.INFO)

def main():
    st = time.time()
    CD = CallDistance()
    cp1 = time.time()
    
    # If the vendor is not MediaTek.
    analysis = MACAnalysis()
    mac_targets = analysis.analyze(CD)
    if len(mac_targets) == 0:
        l.info("mac_targets is empty.")
        return
    cp2 = time.time()

    # If the vendor is MediaTek, mac_targets have to be specified manually.
    # The mac_targets for images in the artifact folder are as follows.
    # Choose the one matched and uncomment it. 
    # Comment out lines 20-25 when you use this.
    """
    mac_targets = [[0x53b2dc, 1]] # P25
    mac_targets = [[0x9047fe14, 1]] # A31
    mac_targets = [[0x903ea598, 1]] # A03s
    mac_targets = [[0x903EEC28, 1]] # A145
    mac_targets = [[0x90481840, 1]] # A315
    """
    # For another image you want to analyze, follow the format above.

    magics = [0x55, 0x44, 0x4b, 0x4e, 0x52, 0x54, 0x46]
    possibles = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4E, 0x50, 0x51, 0x52, 0x53, 0x54, 0x5C, 0x55, 0x56, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x68, 0x69, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD9, 0xDA, 0xDB, 0xE8, 0x0F, 0x00]
    analysis = MsgTypeAnalysis(magics, possibles)
    msg_type_targets = analysis.analyze()
    cp3 = time.time()

    if len(msg_type_targets) == 0:
        l.info("msg_type_targets is empty.")
        return

    analysis = IntegrityFunctionAnalysis()
    integ_probs = analysis.analyze(CD, mac_targets, msg_type_targets)
    cp4 = time.time()

    l.info("Integrity Function Probability")
    for prob in integ_probs:
        l.info("{}: {}".format(hex(prob[0]), prob[1]))

    l.info("Time consumed")
    l.info("Call Graph                  : {}".format(cp1-st))
    l.info("MACAnalysis                 : {}".format(cp2-cp1))
    l.info("MsgTypeAnalysis             : {}".format(cp3-cp2))
    l.info("IntegrityFunctionAnalysis   : {}".format(cp4-cp3))
    l.info("--------------------------------------")
    l.info("Total time                  : {}\n".format(cp4-st))

if __name__ == "__main__":
    # Setup logging
    log_file = os.path.join(os.path.dirname(idc.get_idb_path()), "results.txt")
    logging.basicConfig(filename=log_file)
    
    main()
