import os
import random
import shutil
import string
import win32net
import win32security
from collections import defaultdict
from copy import deepcopy
from enum import Enum
from typing import List

import ntsecuritycon
import win32con
import win32netcon

from kmeans import k_means

ROOT_FOLDER = 'c:/test_dir/'
ADMIN_NAME = 'Enot'
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


class NormalizedRight(object):
    @staticmethod
    def normalized_ace(ace: Ace):
        right = 0b0
        if ace.type == AceType.ALLOWED:
            if win32con.GENERIC_READ & ace.right:
                right |= 0b001
            if (win32con.GENERIC_WRITE | ntsecuritycon.FILE_READ_ATTRIBUTES) & ace.right:
                right |= 0b010
            if win32con.GENERIC_EXECUTE & ace.right:
                right |= 0b100
        else:
            if ntsecuritycon.FILE_READ_DATA & ace.right:
                right |= 0b001 << 3
            if ntsecuritycon.FILE_WRITE_DATA & ace.right:
                right |= 0b010 << 3
            if ntsecuritycon.FILE_EXECUTE & ace.right:
                right |= 0b100 << 3
        return right

    @staticmethod
    def real_right(user_name: str, normalized_right: int) -> List[Ace]:
        result = []
        res_right = NormalizedRight.real_allow_right(normalized_right)
        if res_right != 0:
            result.append(Ace(user_name, res_right))

        res_right = NormalizedRight.real_deny_right(normalized_right)
        if res_right != 0:
            result.append(Ace(user_name, res_right, AceType.DENIED))

        return result

    @staticmethod
    def real_allow_right(right):
        res_right = 0b0
        if 0b001 & right:
            res_right |= win32con.GENERIC_READ
        if 0b010 & right:
            res_right |= win32con.GENERIC_WRITE | ntsecuritycon.FILE_READ_ATTRIBUTES
        if 0b100 & right:
            res_right |= win32con.GENERIC_EXECUTE
        return res_right

    @staticmethod
    def real_deny_right(right):
        res_right = 0b0
        if (0b001 << 3) & right:
            res_right |= ntsecuritycon.FILE_READ_DATA
        if (0b010 << 3) & right:
            res_right |= ntsecuritycon.FILE_WRITE_DATA
        if (0b100 << 3) & right:
            res_right |= ntsecuritycon.FILE_EXECUTE
        return res_right

    @staticmethod
    def is_allow(right: int):
        return right < 8

    @staticmethod
    def print(right):
        print("{:0>6b}".format(right))

    @staticmethod
    def effective_right(right):
        if right & 0b111000 == 0:
            return right
        return right & (0b111000 | (~right) >> 3)

    @staticmethod
    def is_equal(r1, r2):
        return (r1 | 0b111000) == (r2 | 0b111000)


class WinApi(object):
    def __init__(self):
        self.all_info = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
        self.pwr_sid = win32security.LookupAccountName(None, ADMIN_NAME)[0]

    def set_right(self, object_name: str, rights_list: List[Ace]):
        sd = win32security.GetNamedSecurityInfo(object_name, win32security.SE_FILE_OBJECT, self.all_info)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            dacl = win32security.ACL()

        for ace in rights_list:
            sid = win32security.LookupAccountName(None, ace.name)[0]
            if ace.type == AceType.ALLOWED:
                dacl.AddAccessAllowedAceEx(dacl.GetAclRevision(), win32con.OBJECT_INHERIT_ACE, ace.right, sid)
            if ace.type == AceType.DENIED:
                dacl.AddAccessDeniedAceEx(dacl.GetAclRevision(), win32con.OBJECT_INHERIT_ACE, ace.right, sid)
        win32security.SetNamedSecurityInfo(object_name, win32security.SE_FILE_OBJECT, self.all_info, self.pwr_sid,
                                           self.pwr_sid, dacl, None)

    def add_right(self, object_name: str, ace: Ace):
        sd = win32security.GetNamedSecurityInfo(object_name, win32security.SE_FILE_OBJECT, self.all_info)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            dacl = win32security.ACL()

        sid = win32security.LookupAccountName(None, ace.name)[0]
        if ace.type == AceType.ALLOWED:
            dacl.AddAccessAllowedAceEx(dacl.GetAclRevision(), win32con.OBJECT_INHERIT_ACE, ace.right, sid)
        if ace.type == AceType.DENIED:
            dacl.AddAccessDeniedAceEx(dacl.GetAclRevision(), win32con.OBJECT_INHERIT_ACE, ace.right, sid)
        win32security.SetNamedSecurityInfo(object_name, win32security.SE_FILE_OBJECT, self.all_info, self.pwr_sid,
                                           self.pwr_sid, dacl, None)

    def delete_ace(self, object_path: str, aceInfo: Ace):
        sd = win32security.GetFileSecurity(object_path, self.all_info)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return 0
        else:
            for ace_no in range(0, dacl.GetAceCount()):
                _ace = dacl.GetAce(ace_no)
                ace = Ace(win32security.LookupAccountSid(None, _ace[2])[0],
                          self.convert_real_ace_right(_ace[1], _ace[0][0]),
                          AceType(_ace[0][0]))
                if ace.name == aceInfo.name:
                    if ace.type == aceInfo.type and ace.right == aceInfo.right:
                        dacl.DeleteAce(ace_no)
                        win32security.SetNamedSecurityInfo(object_path, win32security.SE_FILE_OBJECT, self.all_info,
                                                           self.pwr_sid, self.pwr_sid, dacl, None)
                        return 1
                    return 0

    @staticmethod
    def convert_real_ace_right(right: int, type: int) -> int:
        ace_right = 0
        if type == 0:
            if ntsecuritycon.FILE_GENERIC_READ & right == ntsecuritycon.FILE_GENERIC_READ:
                ace_right |= win32con.GENERIC_READ
            if ntsecuritycon.FILE_GENERIC_WRITE & right == ntsecuritycon.FILE_GENERIC_WRITE:
                ace_right |= win32con.GENERIC_WRITE | ntsecuritycon.FILE_READ_ATTRIBUTES
            if ntsecuritycon.FILE_GENERIC_EXECUTE & right == ntsecuritycon.FILE_GENERIC_EXECUTE:
                ace_right |= win32con.GENERIC_EXECUTE
        else:
            if ntsecuritycon.FILE_READ_DATA & right == ntsecuritycon.FILE_READ_DATA:
                ace_right |= ntsecuritycon.FILE_READ_DATA
            if ntsecuritycon.FILE_WRITE_DATA & right == ntsecuritycon.FILE_WRITE_DATA:
                ace_right |= ntsecuritycon.FILE_WRITE_DATA
            if ntsecuritycon.FILE_EXECUTE & right == ntsecuritycon.FILE_EXECUTE:
                ace_right |= ntsecuritycon.FILE_EXECUTE

        return ace_right

    @staticmethod
    def file_from_real_file(current_dir: str, file_name: str):
        sd = win32security.GetFileSecurity(os.path.join(current_dir, file_name),
                                           win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return File(file_name, [])
        else:
            rights_list = defaultdict(lambda: 0)
            for ace_no in range(0, dacl.GetAceCount()):
                ace = dacl.GetAce(ace_no)
                user_name = win32security.LookupAccountSid(None, ace[2])[0]
                if USER_SUBNAME in user_name:
                    ace = Ace(user_name, WinApi.convert_real_ace_right(ace[1], ace[0][0]), AceType(ace[0][0]))
                    rights_list[user_name] |= NormalizedRight.normalized_ace(ace)

            res = []
            for x in rights_list:
                res.extend(NormalizedRight.real_right(x, NormalizedRight.effective_right(rights_list[x])))
            return File(file_name, res)


class File(object):
    def __init__(self, name: str, rights_list: List[Ace]):
        self.name = name
        self.rights_list = rights_list

    def create_real_file(self, win_api: WinApi):
        if not os.path.exists(ROOT_FOLDER):
            os.mkdir(ROOT_FOLDER)
        file_name = os.path.join(ROOT_FOLDER, self.name)
        with open(file_name, 'w'): pass
        win_api.set_right(file_name, self.rights_list)

    def get_user_mask(self, user: str):
        mask = 0
        for ace in self.rights_list:
            if ace.name == user:
                mask |= NormalizedRight.normalized_ace(ace)
        return mask

    def change_right(self, user: str, deny_new_right: int):
        for ace in self.rights_list:
            if ace.name == user and ace.type == AceType.DENIED:
                ace.right |= NormalizedRight.real_right(user, deny_new_right)[0].right
        self.rights_list.extend(NormalizedRight.real_right(user, deny_new_right))

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
        users = random.sample(self.users, length)
        ace_list = []
        for _ in range(length):
            ace_list.extend(NormalizedRight.real_right(users.pop(), self.generate_random_right()))
        return ace_list

    def probably_invert_rights(self, file: File) -> File:
        for ace in file.rights_list:
            if random.randint(1, 100) <= self.prob_inverting:
                if ace.type == AceType.ALLOWED:
                    ace.type = AceType.DENIED
                    ace.right = NormalizedRight.real_deny_right(self.generate_random_denied_right())
                else:
                    ace.type = AceType.ALLOWED
                    ace.right = NormalizedRight.real_deny_right(self.generate_random_allowed_right())
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
        print("Possible number of ACE after optimisation: {0} ({1}) {2:.2%}".format(
            ace_count, self.number_of_ace, (1 - ace_count / self.number_of_ace)))
        return 1 - ace_count / self.number_of_ace

    @staticmethod
    def generate_random_allowed_right():
        return random.choice([1, 2, 3, 5, 7])

    @staticmethod
    def generate_random_denied_right():
        return Test.generate_random_allowed_right() << 3

    @staticmethod
    def generate_random_right():
        if random.random() < 0.5:
            return Test.generate_random_allowed_right()
        else:
            return Test.generate_random_denied_right()


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

    def save_result(self, vectors, clusters):
        with open("out.txt", 'w') as output:
            for centroid, cluster_items in clusters.items():
                output.write('centroid {}\n'.format(str(centroid)))
                for vector_index in cluster_items:
                    output.write('{} {}\n'.format(self.files[vector_index].name, str(vectors[vector_index])))

        folder_number = 0
        win_api = WinApi()
        real_ace_count = 0
        for cluster in clusters.values():
            rights_list = []
            new_file = {}
            for i in cluster:
                new_file[i] = deepcopy(self.files[i])

            for i in range(len(self.users)):
                number_aces_for_object = defaultdict(lambda: 0)
                for vector_index in cluster:
                    number_aces_for_object[vectors[vector_index][i]] += 1
                number_aces_for_object = sorted(number_aces_for_object.items(), key=lambda v: v[1], reverse=True)

                if number_aces_for_object[0][0] != 0:
                    if number_aces_for_object[0][1] != len(cluster):
                        # inherit only allowed right
                        if NormalizedRight.is_allow(number_aces_for_object[0][0]):
                            for file in new_file.values():
                                initial_r = file.get_user_mask(self.users[i])
                                effective_r = NormalizedRight.effective_right(initial_r | number_aces_for_object[0][0])
                                if initial_r != effective_r:
                                    new_deny_right = initial_r ^ effective_r
                                    file.change_right(self.users[i], new_deny_right << 3)
                            rights_list.extend(NormalizedRight.real_right(self.users[i], number_aces_for_object[0][0]))
                    else:
                        rights_list.extend(NormalizedRight.real_right(self.users[i], number_aces_for_object[0][0]))

            real_ace_count += len(rights_list)
            for i in new_file.values():
                real_ace_count += len(i.rights_list)
                i.create_real_file(win_api)

            folder = os.path.join(ROOT_FOLDER, str(folder_number))
            os.mkdir(folder)
            folder_number += 1
            for file_index in cluster:
                os.rename(os.path.join(ROOT_FOLDER, new_file[file_index].name),
                          os.path.join(folder, new_file[file_index].name))

                for ace in rights_list:
                    real_ace_count -= win_api.delete_ace(os.path.join(folder, new_file[file_index].name), ace)

                win_api.set_right(folder, rights_list)
                self.check_rights(self.files[file_index], folder)
        print("Real number of ACE after optimisation: {0} ({1}) {2:.2%}".format(
            real_ace_count, self.number_of_ace, (1 - real_ace_count / self.number_of_ace)))

    def check_rights(self, file: File, current_dir: str):
        l1 = WinApi.file_from_real_file(current_dir, file.name).get_file_vector(self.users)
        l2 = file.get_file_vector(self.users)

        if l1 != l2:
            for i in range(len(l1)):
                assert NormalizedRight.is_equal(l1[i], l2[i])


def main():
    from test_config import test_config
    if test_config['real']:
        test = RealTest(config=test_config)
    else:
        test = MockTest(config=test_config)
    test.start_test()


if __name__ == '__main__':
    main()
