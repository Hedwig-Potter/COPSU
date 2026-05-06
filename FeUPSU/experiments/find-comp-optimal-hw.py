# 根据 data.yaml 中的配置，遍历不同的有效安全参数并搜索最合适的汉明权重

import yaml
import os
import sys
import subprocess
import numpy as np
import matplotlib.pyplot as plt

def valid_hw(bl, hw):
    """判断给定的汉明权重 hw 是否满足实验约束条件"""
    if hw > bl/2:
        # 约束：权重大于二分之一时编码开销过大
        return False
    if hw < 1:
        # 权重至少为 1
        return False
    if bl / hw > 13: return False
    # 以下是针对高位宽情况的启发式约束，防止搜索空间过大
    if bl > 12 and hw > bl / 2 - 1: # 略微放宽，确保 bl=19 时能取到 h=8
        return False
    # if bl > 24 and hw > bl / 2 - 4:
    #     return False
    # if bl > 28 and hw > bl / 2 - 6:
    #     return False
        
    return True
    
PATH_TO_MAIN2 = '../build/main2'
# 该二进制包含仅针对寻找最优 hw 的特化入口

# Read data.yaml
with open('data.yaml') as f:
    data = yaml.load(f, Loader=yaml.FullLoader)
    params = data['find_comp_hw']
    # repeat 控制同一参数的重复次数，用于平滑随机波动
    for rep in range(params['repeat']):
        for bl in params['effective_bitlength']:
            for hw in range(1, bl):
                # 跳过不满足限制的组合
                if not valid_hw(bl, hw):
                    continue
                if hw <= 3:
                    continue
                cmd = PATH_TO_MAIN2 + ' ' + \
                    f"-l {bl} " \
                    f"-h {hw} " \
                    f""
                # 通过子进程执行可执行文件并收集输出；便于后续可视化
                res=subprocess.run(cmd, shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
        # 每轮重复结束打印提示，追踪进度
        print(f"Finished {rep}")