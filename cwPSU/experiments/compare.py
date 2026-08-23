"""
Use the compare_w_dipsi configuration in data.yaml to invoke `build/main`
and compare PEPSI with DI-PSI across the configured parameter combinations.
"""

import yaml
import subprocess

PATH_TO_MAIN = '../build/main'

with open('data.yaml') as f:
    data = yaml.load(f, Loader=yaml.FullLoader)
    params = data['compare_w_dipsi']
    for rep in range(params['repeat']):
        for mu in params['mu']:
            for type in [1,2]:
                cmd = PATH_TO_MAIN + " " \
                    f"-m {mu} " \
                    f"-t PSISum " \
                    f"-x {type} "
                res=subprocess.run(cmd, shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
        print(f"Finished {rep}")
