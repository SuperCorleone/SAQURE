#!/usr/bin/env python3
import os
import sys
import glob


def main():
    # 获取当前目录下所有 .pddl 文件
    pddl_files = glob.glob("*.pddl")
    
    if not pddl_files:
        print("当前目录下没有找到 .pddl 文件。")
        return
    
    print(f"找到 {len(pddl_files)} 个 .pddl 文件，开始处理...\n")
    for filepath in pddl_files:
        filename = os.path.splitext(os.path.basename(filepath))[0]
        
        # 检查文件是否存在
        if not os.path.exists(filepath):
            print(f"错误：文件 '{filepath}' 不存在", file=sys.stderr)
            sys.exit(1)
        
        # 读取所有行
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        # 修改前两行（如果存在）
        if len(lines) >= 1:
            lines[0] = f"(define (problem AEDI-{filename})\n"
        if len(lines) >= 2:
            lines[1] = "(:domain AED)\n"
        
        # 将以 ";;" 开头的行替换为空行（忽略行首空白）
        new_lines = []
        for line in lines:
            if line.lstrip().startswith(';;'):
                continue   # 跳过这一行 new_lines.append('\n')          # 保留为空行
            else:
                new_lines.append(line)
        
        # 写回文件
        with open(filepath, 'w') as f:
            f.writelines(new_lines)
        
        print(f"成功修改文件 '{filepath}'")
    print("成功修改所有本路径下的.pddl文件")

if __name__ == "__main__":
    main()