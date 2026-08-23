"""
Iterate over candidate weights from the find_comp_hw configuration in
data.yaml and invoke `build/main2` to find parameters satisfying the cwPSU
constant-weight optimization constraints.
"""

import yaml
import subprocess

def valid_hw(bl, hw):
    if hw > bl/2:
        return False
    if hw < 1:
        return False
    if bl / hw > 12:
        return False
    if bl > 12 and hw > bl/2-2:
        return False
    if bl > 24 and hw > bl/2-4:
        return False
    if bl > 28 and hw > bl/2-6:
        return False
    return True
    
PATH_TO_MAIN2 = '../build/main2'

with open('data.yaml') as f:
    data = yaml.load(f, Loader=yaml.FullLoader)
    params = data['find_comp_hw']
    for rep in range(params['repeat']):
        for bl in params['effective_bitlength']:
            for hw in range(1, bl):
                if not valid_hw(bl, hw):
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
