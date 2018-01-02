import string
import random
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


def mock_generate_obj(count: int) -> List[str]:
    return [str(x) for x in range(count)]


def mock_generate_random_allowed_right():
    right = AceRight.EMPTY
    right += AceRight.ALLOWED_READ if random.random() < 0.5 else AceRight.EMPTY
    right += AceRight.ALLOWED_WRITE if random.random() < 0.5 else AceRight.EMPTY
    right += AceRight.ALLOWED_EXECUTE if random.random() < 0.5 else AceRight.EMPTY
    return right


def mock_generate_random_denied_right():
    right = AceRight.EMPTY
    right += AceRight.DENIED_READ if random.random() < 0.5 else AceRight.EMPTY
    right += AceRight.DENIED_WRITE if random.random() < 0.5 else AceRight.EMPTY
    right += AceRight.DENIED_EXECUTE if random.random() < 0.5 else AceRight.EMPTY
    return right


def mock_generate_random_right():
    if random.random() < 0.5:
        return mock_generate_random_allowed_right()
    return mock_generate_random_denied_right()


def mock_generate_file(objects: List[str]) -> File:
    number_of_ace = random.randint(1, len(objects) // 2)
    ace_list = [Ace(
        random.choice(objects),  # random object
        mock_generate_random_right()
    ) for _ in range(number_of_ace)]
    return File("test_file" + "".join([random.choice(string.ascii_letters) for _ in range(10)]), ace_list)


def mock_get_file_vector(file: File, objects: List[str]) -> str:
    res = []
    for obj in objects:
        res.append(file.exist_obj_ace(obj))
    return res


def mock_set_obj_right(obj_name: str, file: File) -> bool:
    pass


def mock_generate_files_cluster(number_of_files: int, objects: List[str]) -> List[File]:
    number_of_ace = random.randint(1, len(objects) // 2)
    ace_list = [Ace(
        random.choice(objects),  # random object
        mock_generate_random_right()
    ) for _ in range(number_of_ace)]
    return [File("test_file" + "".join([random.choice(string.ascii_letters) for _ in range(10)]), deepcopy(ace_list))
            for _ in
            range(number_of_files)]


def probably_invert_rights(file: File, probability: int) -> File:
    for ace in file.rights_list:
        if random.randint(0, 99) <= probability:
            if ace.get_type() == ace.ALLOWED:
                ace.right = mock_generate_random_denied_right()
            else:
                ace.right = mock_generate_random_allowed_right()
    return file


def write_result(vectors, clusters, file_name):
    with open(file_name, 'w') as output:
        for centroid, cluster_items in clusters.items():
            output.write('centroid {}\n'.format(str(centroid)))
            for vector_index in cluster_items:
                output.write('{}\n'.format(str(vectors[vector_index])))


def start_test(objects_count: int, files_count: int, clusters_count: int, prob_inverting: int):
    objects = mock_generate_obj(objects_count)
    files_clusters = []
    files = []
    for _ in range(clusters_count):
        f = mock_generate_files_cluster(files_count // clusters_count, objects)
        files_clusters.append(f)
        files.extend(f)
    files.extend([mock_generate_file(objects) for _ in range(files_count % clusters_count)])

    for f in files:
        probably_invert_rights(f, prob_inverting)

    vectors = []
    for f in files:
        vectors.append(mock_get_file_vector(f, objects))
    clusters = k_means(vectors, clusters_count=clusters_count)
    write_result(vectors, clusters, "out.txt")


def main():
    from test_config import test_config
    start_test(test_config['objects'], test_config['files'], test_config['folders'],
               test_config['probability of inverting'])


if __name__ == '__main__':
    main()
