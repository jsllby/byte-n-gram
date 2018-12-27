import os
import binascii
import json
import struct


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


class Dict():
    def __init__(self, beni_train_path, mal_train_path, n=6, step=6, number=600, para=[]):
        self.beni_train_path = beni_train_path
        self.mal_train_path = mal_train_path
        self.n = n
        self.step = step
        self.number = number
        self.count = 0
        self.beni_dict = {}
        self.mal_dict = {}
        self.beni_dict_path = "dict/benign_dic.json"
        self.mal_dict_path = "dict/malicious_dic.json"

    def create_dict(self):
        self.beni_dict = self.create_one_dict(self.beni_train_path, 0)
        self.mal_dict = self.create_one_dict(self.mal_train_path, 1)

        self.beni_dict, self.mal_dict = self.filter(self.beni_dict, self.mal_dict)
        self.beni_dict = self.sort_by_value(self.beni_dict)
        self.mal_dict = self.sort_by_value(self.mal_dict)

    def save_dict(self):
        os.remove(self.beni_dict_path)
        os.remove(self.mal_dict_path)
        with open(self.beni_dict_path, 'w', encoding='utf-8') as json_file:
            json.dump(self.beni_dict, json_file, ensure_ascii=False)

        with open(self.mal_dict_path, 'w', encoding='utf-8') as json_file:
            json.dump(self.mal_dict, json_file, ensure_ascii=False)

    def load_dict(self, beni, mal):
        with open(beni, 'r') as json_file:
            str = json_file.read()
            self.beni_dict = json.loads(str)
        with open(mal, 'r') as json_file:
            str = json_file.read()
            self.mal_dict = json.loads(str)

    def create_one_dict(self, beni_path, type):  # benign:0   malicious:1
        single_dic = {}
        dict = {}
        count = 0
        list = os.listdir(beni_path)
        for f in list:
            abs_path = os.path.join(beni_path, f)
            # count = count + 1
            if (isPE(abs_path) == False):
                continue
            self.count += 1
            # print("count:{}\n".format(count))
            single_dic.clear()

            with open(abs_path, 'rb') as infile:
                byte = infile.read()
                hex = str.upper(binascii.b2a_hex(byte).decode('ascii'))
            cur = 0

            while (cur < len(hex)):
                temp = hex[cur:cur + self.n]
                if len(temp) <= self.n:
                    for i in range(self.n - len(temp)):
                        temp = temp + '0'
                cur = cur + self.step

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

    def should_remove(self, value1, value2):
        if (value1 - value2) < self.count * 0.1:
            return True
        return False

    def filter(self, beni_dict, mal_dict):
        keys = list(beni_dict.keys())
        for key in keys:
            beni_value = beni_dict.get(key)
            if mal_dict.get(key):
                mal_value = mal_dict.get(key)
                if beni_value >= mal_value:
                    del mal_dict[key]
                    if self.should_remove(beni_value, mal_value):
                        del beni_dict[key]
                else:
                    del beni_dict[key]
                    if self.should_remove(mal_value, beni_value):
                        del mal_dict[key]
            else:
                if self.should_remove(beni_value, 0):
                    del beni_dict[key]
        keys = list(mal_dict.keys())
        for key in keys:
            mal_value = mal_dict.get(key)
            if self.should_remove(mal_value, 0):
                del mal_dict[key]

        return beni_dict, mal_dict

    def sort_by_value(self, dict):
        result_dict = {}
        list = sorted(dict.items(), key=lambda asd: asd[1], reverse=True)
        count = 0
        for item in list:
            result_dict[item[0]] = item[1]
            count += 1
            if count >= self.number / 2:
                break
        return result_dict

    def get_statistics(self):
        print("count = {}\n".format(self.count))
        print("beni_dict = {}\nmal_dict = {}\n".format(len(self.beni_dict), len(self.mal_dict)))

    def get_dict(self):
        temp = {}
        temp.update(self.beni_dict)
        temp.update(self.mal_dict)
        return temp

        # return dict(self.beni_dict.items()+self.mal_dict.items())

    def get_dict_path(self):
        return self.beni_dict_path, self.mal_dict_path
