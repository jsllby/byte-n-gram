import CreateDict
import GenerateData
import KNN
import numpy as np

# 大小端：https://www.cnblogs.com/wi100sh/p/4899460.html
# PE类型判断：https://blog.csdn.net/feifa105/article/details/12082743
# struct.pack/unpack 详介：https://blog.csdn.net/weiwangchao_/article/details/80395941

beni_train_path = "sample/benign/small_train"
mal_train_path = "sample/malicious/small_train"

beni_test_path = "sample/benign/small_test"
mal_test_path = "sample/malicious/small_test"

# 生成字典
dict = CreateDict.Dict(beni_train_path, mal_train_path)
# dict.create_dict()
# dict.save_dict()
# dict.get_statistics()
beni_dict_path, mal_dict_path = dict.get_dict_path()
dict.load_dict(beni_dict_path, mal_dict_path)

# print(len(dict.get_dict()))

# 生成数据
data = GenerateData.Data(beni_train_path, mal_train_path, beni_test_path, mal_test_path, dict.get_dict())
# data.generate_data()
# data.save_data()
# data.get_statistics()
train_data_path, test_data_path = data.get_data_path()
train_data, test_data = data.load_data(train_data_path, test_data_path)

knn = KNN.KNN(train_data, 3)
count = 0
acc = 0

for data in test_data:
    label = data[-1]
    predict = knn.classify(data[:len(data) - 1])
    if predict == label:
        acc += 1
    count += 1
    print("{}".format(count))
print("count = {}, acc rate = {}%\n".format(count, acc*100/count))


