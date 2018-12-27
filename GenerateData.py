import os
import struct
import binascii
import numpy as np


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


class Data():
    def __init__(self, beni_train_path, mal_train_path, beni_test_path, mal_test_path, dict):
        self.beni_train_path = beni_train_path
        self.mal_train_path = mal_train_path
        self.beni_test_path = beni_test_path
        self.mal_test_path = mal_test_path
        self.dict = dict

        self.n = 6
        self.step = 6

        self.train_data = np.zeros(())
        self.test_data = []

        self.train_number = len
        self.train_data_path = "data/train.txt"
        self.test_data_path = "data/test.txt"

    def generate_data(self):
        paths = [self.beni_train_path, self.mal_train_path, self.beni_test_path, self.mal_test_path]
        for i in range(len(paths)):
            count = 0
            label = i % 2  # benign:0  malicious:1
            list = os.listdir(paths[i])
            for f in list:
                abs_path = os.path.join(paths[i], f)
                if (isPE(abs_path) == False):
                    continue
                count += 1
                single_dict = self.create_single_dict(abs_path)
                single_data = self.create_data(single_dict)
                single_data.append(label)
                if i < 2:
                    self.train_data.append(single_data)
                else:
                    self.test_data.append(single_data)

    def save_data(self):
        os.remove(self.test_data_path)
        os.remove(self.test_data_path)
        np.savetxt(self.test_data_path, self.train_data)
        np.savetxt(self.test_data_path, self.test_data)

    def get_statistics(self):
        print("total train data = {}, total test data = {}\n".format(len(self.train_data), len(self.test_data)))

    def create_single_dict(self, path):
        single_dict = {}

        with open(path, 'rb') as infile:
            byte = infile.read()
            hex = str.upper(binascii.b2a_hex(byte).decode('ascii'))
        cur = 0

        while (cur < len(hex)):
            temp = hex[cur:cur + self.n]
            if len(temp) <= self.n:
                for i in range(self.n - len(temp)):
                    temp = temp + '0'
            cur = cur + self.step
            if single_dict.get(temp):
                single_dict[temp] = single_dict.get(temp) + 1
            else:
                single_dict[temp] = 1
        return single_dict

    def create_data(self, single_dict):
        keys = list(self.dict.keys())
        data = []
        for key in keys:
            if (single_dict.get(key)):
                data.append(single_dict.get(key) * self.dict.get(key))
            else:
                data.append(0)
        return data

    def get_data_path(self):
        return self.train_data_path, self.test_data_path

    def load_data(self, train_data_path, test_data_path):
        self.train_data = np.loadtxt(train_data_path)
        self.test_data = np.loadtxt(test_data_path)
        return self.train_data, self.test_data
