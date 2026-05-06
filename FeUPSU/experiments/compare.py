# 从 data.yaml 中读取“与 DIPSI 比较”实验参数，并枚举不同的 μ 和优化类型

import yaml
import os
import sys
import subprocess
import numpy as np
import matplotlib.pyplot as plt    

PATH_TO_MAIN = '../build/main'
# 指向已构建的主程序，可通过 scripts/build.sh 生成

# Read data.yaml
with open('data.yaml') as f:
    data = yaml.load(f, Loader=yaml.FullLoader)
    params = data['compare_w_dipsi']
    # 外层循环用于重复实验以获得更稳定的统计结果
    for rep in range(params['repeat']):
        # 遍历不同的桶容量 μ，对应论文中不同规模的数据集
        for mu in params['mu']:
            # type=1 表示通信优化，type=2 表示计算优化
            for type in [1,2]:
                cmd = PATH_TO_MAIN + " " \
                    f"-m {mu} " \
                    f"-t PSISum " \
                    f"-x {type} "
                # shell=True 允许直接拼接命令字符串；stdout/stderr 捕获用于后续分析
                res=subprocess.run(cmd, shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
        # 每次重复完成后输出提示，方便观察进度
        print(f"Finished {rep}")