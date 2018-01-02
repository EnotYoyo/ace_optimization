import string
import random
from collections import defaultdict
from typing import List
from kmeans import k_means
from copy import deepcopy

ROOT_FOLDER = 'c:/test_dir/'


class AceRight(object):
    # |  5 |  4 |  3 | 2 | 1 | 0 |
    # | 32 | 16 |  8 | 4 | 2 | 1 |
    # | 63 | 31 | 15 | 7 | 3 | 1 |
    EMPTY = 0b0
    ALLOWED_READ = 0b000001
    ALLOWED_WRITE = 0b000010
    ALLOWED_EXECUTE = 0b000100
    DENIED_READ = 0b001000
    DENIED_WRITE = 0b010000
    DENIED_EXECUTE = 0b100000


class Ace(object):
    ALLOWED = 0
    DENIED = 1

    def __init__(self, name: str, right: int, inherit: bool = False):
        self.name = name
        self.right = right
        self.inherit = inherit

    def get_type(self):
        if self.right <= 7:
            return self.ALLOWED
        return self.DENIED


class File(object):
    def __init__(self, name: str, rights_list: List[Ace]):
        self.name = name
        self.rights_list = rights_list

    def exist_obj_ace(self, obj: str):
        for right in self.rights_list:
            if right.name == obj:
                return right.right
        return AceRight.EMPTY

    def get_file_vector(self, objects: List[str]) -> List[int]:
        res = []
        for obj in objects:
            res.append(self.exist_obj_ace(obj))
        return res


class Test(object):
    def __init__(self, config: dict):
        self.objects_count = config['objects']
        self.files_count = config['files']
        self.folders = config['folders']
        self.clusters_count = config['clusters count']
        self.prob_inverting = config['probability of inverting']
        self.real_test = config['real']
        self.files_per_cluster = self.files_count // self.folders

        self.objects = []
        self.files = []

    def start_test(self):
        if not self.real_test:
            self.replace_real_function()

        self.objects = self.generate_obj()
        for _ in range(self.folders):
            self.files.extend(self.generate_files_cluster())

        # if files_count % clusters_count != 0 then generating additional files
        self.files.extend([self.generate_file() for _ in range(self.files_count % self.folders)])

        for file in self.files:
            self.probably_invert_rights(file)

        self.print_number_of_ace()

        for i in self.clusters_count:
            print("Number of clusters: ", i)
            vectors = []
            for file in self.files:
                vectors.append(file.get_file_vector(self.objects))
            clusters = k_means(vectors, clusters_count=i)
            self.optimize_ace(clusters, vectors)
            self.save_result(vectors, clusters)

    def replace_real_function(self):
        self.generate_obj = self._mock_generate_obj
        self.generate_file = self._mock_generate_file
        self.generate_files_cluster = self._mock_generate_files_cluster
        self.save_result = self._mock_save_result

    def _mock_generate_obj(self) -> List[str]:
        return [str(x) for x in range(self.objects_count)]

    def generate_obj(self) -> List[str]:
        raise NotImplementedError

    def _mock_generate_file(self) -> File:
        number_of_ace = random.randint(1, self.objects_count // 2)
        ace_list = [Ace(
            random.choice(self.objects),  # random object
            self.generate_random_right()
        ) for _ in range(number_of_ace)]
        return File("test_file" + "".join([random.choice(string.ascii_letters) for _ in range(10)]), ace_list)

    def generate_file(self, objects: List[str]) -> File:
        raise NotImplementedError

    def _mock_generate_files_cluster(self) -> List[File]:
        number_of_ace = random.randint(1, self.objects_count // 2)
        rand_objects = iter(random.sample(self.objects, number_of_ace))
        ace_list = [Ace(
            next(rand_objects),
            self.generate_random_right()
        ) for _ in range(number_of_ace)]
        return [
            File("test_file" + "".join([random.choice(string.ascii_letters) for _ in range(10)]), deepcopy(ace_list))
            for _ in
            range(self.files_per_cluster)]

    def generate_files_cluster(self) -> List[File]:
        raise NotImplementedError

    def probably_invert_rights(self, file: File) -> File:
        for ace in file.rights_list:
            if random.randint(0, 99) <= self.prob_inverting:
                if ace.get_type() == ace.ALLOWED:
                    ace.right = self.generate_random_denied_right()
                else:
                    ace.right = self.generate_random_allowed_right()
        return file

    def print_number_of_ace(self):
        number = 0
        for file in self.files:
            number += len(file.rights_list)
        self.number_of_ace = number
        print("Number of ACE: ", number)

    def _mock_save_result(self, vectors, clusters):
        with open("out.txt", 'w') as output:
            for centroid, cluster_items in clusters.items():
                output.write('centroid {}\n'.format(str(centroid)))
                for vector_index in cluster_items:
                    output.write('{}\n'.format(str(vectors[vector_index])))

    def save_result(self, vectors, clusters):
        raise NotImplementedError

    def optimize_ace(self, clusters, vectors):
        ace_count = 0
        for cluster in clusters.values():
            for i in range(self.objects_count):
                number_aces_for_object = defaultdict(lambda: 0)
                for vector_index in cluster:
                    number_aces_for_object[vectors[vector_index][i]] += 1
                number_aces_for_object = sorted(number_aces_for_object.items(), key=lambda v: v[1], reverse=True)
                if number_aces_for_object[0][0] != 0:
                    ace_count += 1
                for i in number_aces_for_object[1:]:
                    if i[0] == 0:
                        ace_count += i[1]
                    else:
                        ace_count += i[1] * 2
        print("Number of ACE after optimisation: {0} ({1}) {2:.2%}".format(ace_count, self.number_of_ace,
                                                                           (1 - ace_count / self.number_of_ace)))

    @staticmethod
    def generate_random_allowed_right():
        return random.randint(1, 7)

    @staticmethod
    def generate_random_denied_right():
        return random.randint(1, 7) << 3

    @staticmethod
    def generate_random_right():
        if random.random() < 0.4:
            return Test.generate_random_allowed_right()
        elif random.random() < 0.7:
            return Test.generate_random_denied_right()
        else:
            return Test.generate_random_allowed_right() + Test.generate_random_denied_right()


def main():
    from test_config import test_config
    test = Test(config=test_config)
    test.start_test()


if __name__ == '__main__':
    main()
