import os
import binascii
import collections
import json
import struct

# 大小端：https://www.cnblogs.com/wi100sh/p/4899460.html
# PE类型判断：https://blog.csdn.net/feifa105/article/details/12082743
# struct.pack/unpack 详介：https://blog.csdn.net/weiwangchao_/article/details/80395941

N = 6
COUNT = 200


def isPE(path):
    # 1. PE文件一定是MZ（0x4D5A）起头的
    file = open(path, "rb")
    data = struct.unpack("h", file.read(2))[0]  # struct.unpack 的返回类型和tuple
    if (data != 23117):  # B(MZ) = 01001101 01011010  小端存储： 01011010 01001101 -> 十进制为23117
        return False

    # 2. 3C位置的值指向的值是PE（0x5045)
    file.seek(60, 0)  # 0x3C = 60
    data = struct.unpack("h", file.read(2))[0]
    file.seek(data, 0)
    data = struct.unpack("h", file.read(2))[0]
    if (data != 17744):  # B(PE) = 01010000 01000101  小端存储： 01000101 01010000 -> 十进制为17744
        return False

    return True


def create_dict(beni_path, type):  # benign:0   malicious:1
    single_dic = {}
    dict = {}
    count = 0
    list = os.listdir(beni_path)
    for f in list:
        abs_path = os.path.join(beni_path, f)
        # count = count + 1
        if (isPE(abs_path) == False):
            continue
        # print("count:{}\n".format(count))
        single_dic.clear()

        with open(abs_path, 'rb') as infile:
            byte = infile.read()
            hex = str.upper(binascii.b2a_hex(byte).decode('ascii'))
        cur = 0

        while (cur < len(hex)):
            temp = hex[cur:cur + N]
            if len(temp) <= N:
                for i in range(N - len(temp)):
                    temp = temp + '0'
            cur = cur + N

            # 同一个文件里的相同N-gram不累计
            if single_dic.get(temp):
                single_dic[temp] = single_dic.get(temp) + 1
            else:
                single_dic[temp] = 1
                if dict.get(temp):
                    dict[temp] = dict.get(temp) + 1
                else:
                    dict[temp] = 1

            # 同一个文件里的相同N-gram累计
            # if dict.get(temp):
            #     dict[temp] = dict.get(temp) + 1
            # else:
            #     dict[temp] = 1
    return dict


def should_remove(value1, value2):
    if (value1 - value2) < COUNT * 0.2:
        return True
    return False


def filter(beni_dict, mal_dict):
    beni_del = []
    mal_del = []
    keys = list(beni_dict.keys())
    for key in keys:
        beni_value = beni_dict.get(key)
        if mal_dict.get(key):
            mal_value = mal_dict.get(key)
            if beni_value >= mal_value:
                del mal_dict[key]
                if should_remove(beni_value, mal_value):
                    del beni_dict[key]
            else:
                del beni_dict[key]
                if should_remove(mal_value, beni_value):
                    del mal_dict[key]
        else:
            if should_remove(beni_value, 0):
                del beni_dict[key]
    keys = list(mal_dict.keys())
    for key in keys:
        mal_value = mal_dict.get(key)
        if should_remove(mal_value, 0):
            del mal_dict[key]

    return beni_dict, mal_dict


def main():
    beni_train_path = "data/benign/small_train"
    mal_train_path = "data/malicious/small_train"
    beni_test_path = "data/benign/small_test"
    mal_test_path = "data/malicious/small_test"
    beni_dict_path = "benign_dic.json"
    mal_dict_path = "malicious_dic.json"

    beni_dict = create_dict(beni_train_path, 0)
    mal_dict = create_dict(mal_train_path, 1)

    with open("beni_dict.json", 'w', encoding='utf-8') as json_file:
        json.dump(beni_dict, json_file, ensure_ascii=False)

    with open("mal_dict.json", 'w', encoding='utf-8') as json_file:
        json.dump(mal_dict, json_file, ensure_ascii=False)

    count = 0
    for k in beni_dict.keys():
        count += 1
    print("count = {}\n".format(count))

    count = 0
    for k in mal_dict.keys():
        count += 1
    print("count = {}\n".format(count))


if __name__ == '__main__':
    main()
