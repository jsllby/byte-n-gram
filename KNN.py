import numpy as np


class KNN():
    def __init__(self, data, k):
        self.data = data
        self.k = k
        print(self.data.shape[1])

    def classify(self, input):
        dist_list = []
        label_list = []
        for t in self.data:
            label = t[-1]
            t = t[:len(t) - 1]
            dist = 0
            for i in range(len(t)):
                dist += (t[i] - input[i]) ** 2
            dist = dist ** 0.5
            dist_list.append(dist)
            label_list.append(label)
        sort = np.argsort(dist_list)

        predict = 0
        for i in range(self.k):
            predict += label_list[sort[i]]
        if predict >= self.k / 2:
            predict = 1
        else:
            predict = 0
        return predict
