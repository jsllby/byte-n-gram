import os
import binascii
import collections
import json

N = 6
COUNT = 200

def create_dict(beni_path, mal_path):
    single_dic = {}
    beni_dict = {}
    mal_dict = {}

    paths = [beni_path, mal_path]
    for path in paths:
        list = os.listdir(path)
        for f in list:
            single_dic.clear()
            with open(os.path.join(path, f), 'rb') as infile:
                byte = infile.read()
                hex = str.upper(binascii.b2a_hex(byte).decode('ascii'))
            cur = 0

            while (cur < len(hex)):
                temp = hex[cur:cur + N]
                if len(temp) <= N:
                    for i in range(N - len(temp)):
                        temp = temp + '0'
                cur = cur + N
                if single_dic.get(temp):
                    single_dic[temp] = single_dic.get(temp) + 1
                else:
                    single_dic[temp] = 1
                    if path == beni_path:
                        if beni_dict.get(temp):
                            beni_dict[temp] = beni_dict.get(temp) + 1
                        else:
                            beni_dict[temp] = 1
                    else:
                        if mal_dict.get(temp):
                            mal_dict[temp] = mal_dict.get(temp) + 1
                        else:
                            mal_dict[temp] = 1

    return beni_dict, mal_dict


def should_remove(value1, value2):
    if (value1-value2)<COUNT*0.2:
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

    beni_dict, mal_dict = create_dict(beni_train_path, mal_train_path)
    beni_dict, mal_dict = filter(beni_dict, mal_dict)
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
