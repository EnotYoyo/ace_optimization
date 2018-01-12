import string
import shutil
import random
from collections import defaultdict
from enum import Enum
from typing import List

import win32con

from kmeans import k_means
from copy import deepcopy
import win32net, win32security
import win32netcon, ntsecuritycon
import os

ROOT_FOLDER = 'c:/test_dir/'
ADMIN_NAME = 'enot'
USER_SUBNAME = "LabUser"


class AceType(Enum):
    ALLOWED = ntsecuritycon.ACCESS_ALLOWED_ACE_TYPE
    DENIED = ntsecuritycon.ACCESS_DENIED_ACE_TYPE


class Ace(object):
    def __init__(self, name: str, right: int, type: AceType = AceType.ALLOWED):
        self.name = name
        self.right = right
        self.type = type

    def __eq__(self, other):
        if isinstance(other, Ace):
            return self.name == other.name and self.type == other.type and self.right == other.right
        raise ValueError


def convert_real_ace_right(right: int) -> int:
    ace_right = 0
    if ntsecuritycon.FILE_GENERIC_READ & right == ntsecuritycon.FILE_GENERIC_READ:
        ace_right += win32con.GENERIC_READ
    if ntsecuritycon.FILE_GENERIC_WRITE & right == ntsecuritycon.FILE_GENERIC_WRITE:
        ace_right += win32con.GENERIC_WRITE
    if ntsecuritycon.FILE_GENERIC_EXECUTE & right == ntsecuritycon.FILE_GENERIC_EXECUTE:
        ace_right += win32con.GENERIC_EXECUTE

    return ace_right


def set_right(object_name: str, rights_list: List[Ace]):
    all_info = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    sd = win32security.GetNamedSecurityInfo(object_name, win32security.SE_FILE_OBJECT, all_info)
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        dacl = win32security.ACL()

    for ace in rights_list:
        sid = win32security.LookupAccountName(None, ace.name)[0]
        if os.path.isdir(object_name):
            if ace.type == AceType.ALLOWED:
                dacl.AddAccessAllowedAceEx(dacl.GetAclRevision(), win32con.OBJECT_INHERIT_ACE, ace.right, sid)
            if ace.type == AceType.DENIED:
                dacl.AddAccessDeniedAceEx(dacl.GetAclRevision(), win32con.OBJECT_INHERIT_ACE, ace.right, sid)
        else:
            if ace.type == AceType.ALLOWED:
                dacl.AddAccessAllowedAce(dacl.GetAclRevision(), ace.right, sid)
            if ace.type == AceType.DENIED:
                dacl.AddAccessDeniedAce(dacl.GetAclRevision(), ace.right, sid)
    pwr_sid = win32security.LookupAccountName(None, ADMIN_NAME)[0]
    win32security.SetNamedSecurityInfo(object_name, win32security.SE_FILE_OBJECT, all_info, pwr_sid, pwr_sid, dacl,
                                       None)


class File(object):
    def __init__(self, name: str, rights_list: List[Ace]):
        self.name = name
        self.rights_list = rights_list

    def create_real_file(self):
        if not os.path.exists(ROOT_FOLDER):
            os.mkdir(ROOT_FOLDER)
        file_name = os.path.join(ROOT_FOLDER, self.name)
        with open(file_name, 'w'): pass
        set_right(file_name, self.rights_list)

    @staticmethod
    def _normalise_ace_right(ace: Ace) -> int:
        right = 0b0
        if win32con.GENERIC_READ & ace.right:
            right += 0b001
        if win32con.GENERIC_WRITE & ace.right:
            right += 0b010
        if win32con.GENERIC_EXECUTE & ace.right:
            right += 0b100

        if ace.type == AceType.DENIED:
            return right << 3
        else:
            return right

    def get_user_mask(self, user: str):
        mask = 0
        for ace in self.rights_list:
            if ace.name == user:
                mask += self._normalise_ace_right(ace)
        return mask

    def get_file_vector(self, objects: List[str]) -> List[int]:
        res = []
        for obj in objects:
            res.append(self.get_user_mask(obj))
        return res


class Test(object):
    def __init__(self, config: dict):
        self.clusters_count = config['clusters count']
        self.prob_inverting = config['probability of inverting']
        self._number_of_ace = None

        self.users = self.generate_users(config['users'])
        self.files = self.generate_files(config['files'], config['folders'])

    def generate_files(self, files_count: int, folders_count: int) -> List[File]:
        files = []
        for _ in range(folders_count):
            files.extend(self.generate_files_cluster(files_count // folders_count))

        # if files_count % clusters_count != 0 then generating additional files
        files.extend([self.generate_file() for _ in range(files_count % folders_count)])

        return files

    def start_test(self):
        for file in self.files:
            self.probably_invert_rights(file)

        vectors = []
        for file in self.files:
            vectors.append(file.get_file_vector(self.users))

        best_result = -10
        best_clusters = {}
        for i in self.clusters_count:
            print("Number of clusters: ", i)
            clusters = k_means(vectors, clusters_count=i)
            res = self.result(clusters, vectors)
            if res > best_result:
                best_result = res
                best_clusters = clusters

        self.save_result(vectors, best_clusters)

    def generate_users(self, count: int) -> List[str]:
        raise NotImplementedError

    def generate_file(self, ace_list: List[Ace] = None) -> File:
        if ace_list is None:
            ace_list = self.generate_ace_list(random.randint(1, len(self.users)))
        return File("test_file_" + "".join([random.choice(string.ascii_letters) for _ in range(10)]), ace_list)

    def generate_files_cluster(self, count: int) -> List[File]:
        ace_list = self.generate_ace_list(random.randint(1, len(self.users)))
        return [
            File("test_file" + "".join([random.choice(string.ascii_letters) for _ in range(10)]), deepcopy(ace_list))
            for _ in
            range(count)]

    def save_result(self, vectors, clusters):
        raise NotImplementedError

    def generate_ace_list(self, length: int) -> List[Ace]:
        return [Ace(
            random.choice(self.users),
            self.generate_random_right(),
            random.choice(list(AceType))
        ) for _ in range(length)]

    def probably_invert_rights(self, file: File) -> File:
        for ace in file.rights_list:
            if random.randint(1, 100) <= self.prob_inverting:
                if ace.type == AceType.ALLOWED:
                    ace.right = self.generate_random_right()
                    ace.type = AceType.DENIED
                else:
                    ace.right = self.generate_random_right()
                    ace.type = AceType.ALLOWED
        return file

    @property
    def number_of_ace(self):
        if self._number_of_ace is None:
            self._number_of_ace = 0
            for file in self.files:
                self._number_of_ace += len(file.rights_list)
        return self._number_of_ace

    def result(self, clusters, vectors) -> float:
        ace_count = 0
        for cluster in clusters.values():
            for i in range(len(self.users)):
                number_aces_for_object = defaultdict(lambda: 0)
                for vector_index in cluster:
                    number_aces_for_object[vectors[vector_index][i]] += 1
                number_aces_for_object = sorted(number_aces_for_object.items(), key=lambda v: v[1], reverse=True)

                inherit_index = 0
                if number_aces_for_object[inherit_index][0] != 0:
                    if number_aces_for_object[inherit_index][0] > 7:
                        if len([vectors[vector_index][i] < 8 for vector_index in cluster]) != 0:
                            for tmp in number_aces_for_object:
                                if tmp[0] < 8:
                                    inherit_index = number_aces_for_object.index(tmp)
                    ace_count += 1
                for i in number_aces_for_object[0:inherit_index] + number_aces_for_object[inherit_index + 1:]:
                    if i[0] == 0:
                        ace_count += i[1]
                    else:
                        ace_count += i[1] * 2
        print("Number of ACE after optimisation: {0} ({1}) {2:.2%}".format(ace_count, self.number_of_ace,
                                                                           (1 - ace_count / self.number_of_ace)))
        return 1 - ace_count / self.number_of_ace

    @staticmethod
    def generate_random_right():
        all_rights = [win32con.GENERIC_READ, win32con.GENERIC_WRITE, win32con.GENERIC_EXECUTE]
        random.shuffle(all_rights)
        return sum(all_rights[0:random.randint(1, 3)])


class MockTest(Test):
    def __init__(self, config: dict):
        super().__init__(config)

    def save_result(self, vectors, clusters):
        with open("out.txt", 'w') as output:
            for centroid, cluster_items in clusters.items():
                output.write('centroid {}\n'.format(str(centroid)))
                for vector_index in cluster_items:
                    output.write('{} {}\n'.format(self.files[vector_index].name, str(vectors[vector_index])))

    def generate_users(self, count: int) -> List[str]:
        return [str(x) for x in range(count)]


class RealTest(Test):
    def __init__(self, config: dict):
        super().__init__(config)
        for obj in os.listdir(ROOT_FOLDER):
            obj = os.path.join(ROOT_FOLDER, obj)
            if os.path.isdir(obj):
                shutil.rmtree(obj)
            else:
                os.remove(obj)

    def generate_users(self, count: int) -> List[str]:
        obj_list = []
        for x in range(count):
            userName = USER_SUBNAME + str(x)
            try:
                win32net.NetUserDel(None, userName)
            except win32net.error as e:
                pass

            d = {
                'name': userName,
                'password': 'testPassword',
                'priv': win32netcon.USER_PRIV_USER,
                'comment': "User for labs",
                'flags': win32netcon.UF_NORMAL_ACCOUNT | win32netcon.UF_SCRIPT
            }
            win32net.NetUserAdd(None, 1, d)
            obj_list.append(userName)
            # win32net.NetUserDel(self.serverName, userName)
        return obj_list

    def n_right_is_allowed(self, right: int) -> bool:
        return right < 8

    @staticmethod
    def n_right_to_ace_list(user_name: str, right: int) -> List[Ace]:
        result = []
        res_right = 0b0
        if 0b001 & right:
            res_right += win32con.GENERIC_READ
        if 0b010 & right:
            res_right += win32con.GENERIC_WRITE
        if 0b100 & right:
            res_right += win32con.GENERIC_EXECUTE

        if res_right > 0:
            result.append(Ace(user_name, right))

        res_right = 0b0
        if (0b001 << 3) & right:
            res_right += win32con.GENERIC_READ
        if (0b010 << 3) & right:
            res_right += win32con.GENERIC_WRITE
        if (0b100 << 3) & right:
            res_right += win32con.GENERIC_EXECUTE

        if res_right > 0:
            result.append(Ace(user_name, right, AceType.DENIED))

        return result

    def save_result(self, vectors, clusters):
        for file in self.files:
            file.create_real_file()

        with open("out.txt", 'w') as output:
            for centroid, cluster_items in clusters.items():
                output.write('centroid {}\n'.format(str(centroid)))
                for vector_index in cluster_items:
                    output.write('{} {}\n'.format(self.files[vector_index].name, str(vectors[vector_index])))

        folder_number = 0
        for cluster in clusters.values():
            rights_list = []
            for i in range(len(self.users)):
                number_aces_for_object = defaultdict(lambda: 0)
                for vector_index in cluster:
                    number_aces_for_object[vectors[vector_index][i]] += 1
                number_aces_for_object = sorted(number_aces_for_object.items(), key=lambda v: v[1], reverse=True)

                inherit_index = 0
                if number_aces_for_object[inherit_index][0] != 0:
                    if not self.n_right_is_allowed(number_aces_for_object[inherit_index][0]) and \
                            len([self.n_right_is_allowed(vectors[vector_index][i]) for vector_index in
                                 cluster]) != 0:
                        for tmp in number_aces_for_object:
                            if self.n_right_is_allowed(tmp[0]):
                                inherit_index = number_aces_for_object.index(tmp)
                        if inherit_index > 0:
                            rights_list.extend(
                                self.n_right_to_ace_list(self.users[i],
                                                         number_aces_for_object[inherit_index][0]))
                    else:
                        rights_list.extend(
                            self.n_right_to_ace_list(self.users[i], number_aces_for_object[inherit_index][0]))

            folder = os.path.join(ROOT_FOLDER, str(folder_number))
            os.mkdir(folder)
            folder_number += 1
            set_right(folder, rights_list)
            for file_index in cluster:
                os.rename(ROOT_FOLDER + self.files[file_index].name, os.path.join(folder, self.files[file_index].name))
                self.check_rights(self.files[file_index], folder)

    @staticmethod
    def check_rights(file: File, current_dir: str):
        sd = win32security.GetFileSecurity(os.path.join(current_dir, file.name),
                                           win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            raise len(file.rights_list) == 0
        else:
            rights_list = []
            for ace_no in range(0, dacl.GetAceCount()):
                ace = dacl.GetAce(ace_no)
                user_name = win32security.LookupAccountSid(None, ace[2])[0]
                if USER_SUBNAME in user_name:
                    ace = Ace(user_name, convert_real_ace_right(ace[1]), AceType(ace[0][0]))
                    assert ace in file.rights_list
                    rights_list.append(ace)

            assert len(rights_list) == len(file.rights_list)


def main():
    from test_config import test_config
    if test_config['real']:
        test = RealTest(config=test_config)
    else:
        test = MockTest(config=test_config)
    test.start_test()


if __name__ == '__main__':
    main()
