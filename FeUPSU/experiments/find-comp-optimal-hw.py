
import yaml
import os
import sys
import subprocess
import numpy as np
import matplotlib.pyplot as plt

def valid_hw(bl, hw):
    """Return whether the Hamming weight satisfies the experiment constraints."""
    if hw > bl/2:
        return False
    if hw < 1:
        return False
    if bl / hw > 13: return False
    if bl > 12 and hw > bl / 2 - 1:
        return False
    # if bl > 24 and hw > bl / 2 - 4:
    #     return False
    # if bl > 28 and hw > bl / 2 - 6:
    #     return False
        
    return True
    
PATH_TO_MAIN2 = '../build/main2'

# Read data.yaml
with open('data.yaml') as f:
    data = yaml.load(f, Loader=yaml.FullLoader)
    params = data['find_comp_hw']
    for rep in range(params['repeat']):
        for bl in params['effective_bitlength']:
            for hw in range(1, bl):
                if not valid_hw(bl, hw):
                    continue
                if hw <= 3:
                    continue
                cmd = PATH_TO_MAIN2 + ' ' + \
                    f"-l {bl} " \
                    f"-h {hw} " \
                    f""
                res=subprocess.run(cmd, shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
        print(f"Finished {rep}")
