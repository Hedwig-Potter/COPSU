"""
使用 data.yaml 中的 compare_w_dipsi 配置批量调用 `build/main`，
比较 PEPSI 与文献中的 DI-PSI 方案在不同参数组合下的表现。
"""

import yaml
import subprocess
# 离线数据整理和作图在 Notebook 中完成，此处仅保留运行主程序所需的依赖

# `PATH_TO_MAIN` 指向 CMake 构建生成的主可执行文件
PATH_TO_MAIN = '../build/main'

# 从配置文件中读取实验参数，逐一运行被测方案
with open('data.yaml') as f:
    data = yaml.load(f, Loader=yaml.FullLoader)
    params = data['compare_w_dipsi']
    for rep in range(params['repeat']):
        # mu 为服务器集合大小，type 区分不同变体：1=PEPSI，2=DI-PSI
        for mu in params['mu']:
            for type in [1,2]:
                cmd = PATH_TO_MAIN + " " \
                    f"-m {mu} " \
                    f"-t PSISum " \
                    f"-x {type} "
                # 使用 shell 调用可执行文件，收集标准输出便于后续分析
                res=subprocess.run(cmd, shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
        # 每轮实验结束打印提示，便于跟踪长时间批处理
        print(f"Finished {rep}")