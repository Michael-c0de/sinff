from scapy.all import *
from exp_parse import parse_exp

data = rdpcap("./tmp.pcap")

def packet2dict(packet):
    display = {}
    p = packet
    while p:
        display[p.name] = p.fields
        p = p.payload
    return display

sample_dict = packet2dict(data[1])


# import random
# import string
# import re

# # 生成随机字符串，可能包含异常字符
# def random_string(length=10):
#     # 包含字母、数字和特殊字符
#     chars = string.ascii_letters + string.digits + string.punctuation
#     return ''.join(random.choice(chars) for _ in range(length))

# # 随机生成原子表达式，包含随机键和值
# def random_atomic_expression():
#     # 随机生成路径和随机运算符
#     path = random_string(random.randint(1, 10))
#     operator = random.choice(["==", "!=", "=", ">", "<"])
#     value = random_string(random.randint(1, 10))
#     return f"{path}{operator}{value}"

# # 随机生成复合表达式，使用 AND/OR 逻辑链接多个原子表达式
# def random_expression():
#     expression = random_atomic_expression()
    
#     # 随机添加 AND/OR 逻辑
#     for _ in range(random.randint(1, 5)):  # 随机添加1到5个子表达式
#         operator = random.choice(["&&", "||", "|", "&"])
#         expression += f" {operator} {random_atomic_expression()}"
    
#     return expression

# # 测试表达式解析器的安全性
# def fuzz_test():
#     for _ in range(10000*10):  # 生成并测试 10 次
#         exp = random_expression()
#         try:
#             parse_exp(sample_dict, exp)
#         except Exception as e:
#             print(f"Exception occurred: {e}\n")

# # 运行随机测试
# fuzz_test()
