"""
根据 data.yaml 中的 find_comp_hw 配置，遍历候选的权重参数，
调用 `build/main2` 搜索满足 cwPSU 组合优化约束的常权码硬件参数。
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
    
# 指向构建生成的 `main2` 可执行文件
PATH_TO_MAIN2 = '../build/main2'

# 读取配置并挨个尝试有效的 (bitlength, hamming weight) 组合
with open('data.yaml') as f:
    data = yaml.load(f, Loader=yaml.FullLoader)
    params = data['find_comp_hw']
    for rep in range(params['repeat']):
        for bl in params['effective_bitlength']:
            for hw in range(1, bl):
                if not valid_hw(bl, hw):
                    continue
                # 组合满足约束后调用可执行文件，输出写入 stdout 供外部分析
                cmd = PATH_TO_MAIN2 + ' ' + \
                    f"-l {bl} " \
                    f"-h {hw} " \
                    f""
                res=subprocess.run(cmd, shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
        # 打印当前重复轮次完成情况，便于长时间运行时观察进度
        print(f"Finished {rep}")