import string
import random
from collections import defaultdict
from typing import List, Tuple

import win32con

from kmeans import k_means
from copy import deepcopy
import win32net, win32security, win32file, win32api
import win32netcon, ntsecuritycon
import os

ROOT_FOLDER = 'c:/test_dir/'
ADMIN_NAME = 'enot'
USER_SUBNAME = "LabUser"


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
        if self.right < 8:
            return self.ALLOWED
        return self.DENIED

    def get_windows_aces(self) -> Tuple:
        allow_right = deny_right = 0
        if self.right & AceRight.ALLOWED_READ:
            allow_right += win32con.GENERIC_READ
        if self.right & AceRight.ALLOWED_WRITE:
            allow_right += win32con.GENERIC_WRITE
        if self.right & AceRight.ALLOWED_EXECUTE:
            allow_right += win32con.GENERIC_EXECUTE

        if self.right & AceRight.DENIED_READ:
            deny_right += win32con.GENERIC_READ
        if self.right & AceRight.DENIED_WRITE:
            deny_right += win32con.GENERIC_WRITE
        if self.right & AceRight.DENIED_EXECUTE:
            deny_right += win32con.GENERIC_EXECUTE

        return allow_right, deny_right

    def __eq__(self, other):
        if isinstance(other, Ace):
            return self.name == other.name and self.right == other.right
        raise ValueError

    @staticmethod
    def windows_ace_to_ace(right: int, ace_type: int) -> int:
        permissions_file = (
            "DELETE", "READ_CONTROL", "WRITE_DAC", "WRITE_OWNER", "SYNCHRONIZE", "FILE_GENERIC_READ",
            "FILE_GENERIC_WRITE",
            "FILE_GENERIC_EXECUTE", "FILE_DELETE_CHILD")
        for i in permissions_file:
            if getattr(ntsecuritycon, i) & right == getattr(ntsecuritycon, i):
                print("    ", i)
        print('+' * 10)
        ace_right = AceRight.EMPTY
        if ntsecuritycon.FILE_GENERIC_READ & right == ntsecuritycon.FILE_GENERIC_READ:
            ace_right += AceRight.ALLOWED_READ
        if ntsecuritycon.FILE_GENERIC_WRITE & right == ntsecuritycon.FILE_GENERIC_WRITE:
            ace_right += AceRight.ALLOWED_WRITE
        if ntsecuritycon.FILE_GENERIC_EXECUTE & right == ntsecuritycon.FILE_GENERIC_EXECUTE:
            ace_right += AceRight.ALLOWED_EXECUTE

        if ace_type == Ace.DENIED:
            return ace_right << 3
        else:
            return ace_right


def set_right(object_name: str, rights_list: List[Ace]):
    all_info = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    sd = win32security.GetNamedSecurityInfo(object_name, win32security.SE_FILE_OBJECT, all_info)
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        dacl = win32security.ACL()

    for ace in rights_list:
        sid = win32security.LookupAccountName(None, ace.name)[0]
        allow_right, deny_right = ace.get_windows_aces()
        if os.path.isdir(object_name):
            if allow_right != AceRight.EMPTY:
                dacl.AddAccessAllowedAceEx(dacl.GetAclRevision(), win32con.OBJECT_INHERIT_ACE, allow_right, sid)
            if deny_right != AceRight.EMPTY:
                dacl.AddAccessDeniedAceEx(dacl.GetAclRevision(), win32con.OBJECT_INHERIT_ACE, deny_right, sid)
        else:
            if allow_right != AceRight.EMPTY:
                dacl.AddAccessAllowedAce(dacl.GetAclRevision(), allow_right, sid)
            if deny_right != AceRight.EMPTY:
                dacl.AddAccessDeniedAce(dacl.GetAclRevision(), deny_right, sid)
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
        fname = ROOT_FOLDER + self.name
        with open(fname, 'w'): pass
        set_right(fname, self.rights_list)

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
        self.number_of_ace = 0

        self.objects = []
        self.files = []
        self.serverName = None

    def start_test(self):
        if not self.real_test:
            self.replace_real_function()

        self.objects = self.generate_obj()
        for _ in range(self.folders):
            self.files.extend(self.generate_files_cluster())

        # if files_count % clusters_count != 0 then generating additional files
        self.files.extend([self.generate_file() for _ in range(self.files_count % self.folders)])

        for file in self.files:
            print(file.name)
            self.probably_invert_rights(file)

        if self.real_test:
            for file in self.files:
                file.create_real_file()

        self.print_number_of_ace()

        vectors = []
        for file in self.files:
            vectors.append(file.get_file_vector(self.objects))

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

    def replace_real_function(self):
        self.generate_obj = self._mock_generate_obj
        self.generate_file = self._mock_generate_file
        self.generate_files_cluster = self._mock_generate_files_cluster
        self.save_result = self._mock_save_result

    def _mock_generate_obj(self) -> List[str]:
        return [str(x) for x in range(self.objects_count)]

    def generate_obj(self) -> List[str]:
        obj_list = []
        for x in range(self.objects_count):
            userName = USER_SUBNAME + str(x)
            try:
                win32net.NetUserDel(self.serverName, userName)
            except win32net.error as e:
                pass

            d = {
                'name': userName,
                'password': 'testPassword',
                'priv': win32netcon.USER_PRIV_USER,
                'comment': "User for labs",
                'flags': win32netcon.UF_NORMAL_ACCOUNT | win32netcon.UF_SCRIPT
            }
            win32net.NetUserAdd(self.serverName, 1, d)
            obj_list.append(userName)
            # win32net.NetUserDel(self.serverName, userName)
        return obj_list

    def _mock_generate_file(self) -> File:
        number_of_ace = random.randint(1, self.objects_count // 2)
        ace_list = [Ace(
            random.choice(self.objects),  # random object
            self.generate_random_right()
        ) for _ in range(number_of_ace)]
        return File("test_file_" + "".join([random.choice(string.ascii_letters) for _ in range(10)]), ace_list)

    def generate_file(self) -> File:
        number_of_ace = random.randint(1, self.objects_count // 2)
        ace_list = [Ace(
            random.choice(self.objects),  # random object
            self.generate_random_right()
        ) for _ in range(number_of_ace)]
        file = File("test_file" + "".join([random.choice(string.ascii_letters) for _ in range(10)]), ace_list)
        return file

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
        number_of_ace = random.randint(1, self.objects_count // 2)
        rand_objects = iter(random.sample(self.objects, number_of_ace))
        ace_list = [Ace(
            next(rand_objects),
            self.generate_random_right()
        ) for _ in range(number_of_ace)]
        file_list = [
            File("test_file" + "".join([random.choice(string.ascii_letters) for _ in range(10)]), deepcopy(ace_list))
            for _ in
            range(self.files_per_cluster)
        ]
        return file_list

    def probably_invert_rights(self, file: File) -> File:
        for ace in file.rights_list:
            if random.randint(0, 99) <= self.prob_inverting:
                if ace.get_type() == ace.ALLOWED:
                    ace.right = self.generate_random_denied_right()
                else:
                    ace.right = self.generate_random_allowed_right()
        return file

    def print_number_of_ace(self):
        for file in self.files:
            for ace in file.rights_list:
                self.number_of_ace += bool(ace.right & 0b111) + bool(ace.right & 0b111000)
        print("Number of ACE: ", self.number_of_ace)

    def _mock_save_result(self, vectors, clusters):
        with open("out.txt", 'w') as output:
            for centroid, cluster_items in clusters.items():
                output.write('centroid {}\n'.format(str(centroid)))
                for vector_index in cluster_items:
                    output.write('{} {}\n'.format(self.files[vector_index].name, str(vectors[vector_index])))

    def save_result(self, vectors, clusters):
        self._mock_save_result(vectors, clusters)
        folder_number = 0
        for cluster in clusters.values():
            rights_list = []
            for i in range(self.objects_count):
                number_aces_for_object = defaultdict(lambda: 0)
                for vector_index in cluster:
                    number_aces_for_object[vectors[vector_index][i]] += 1
                number_aces_for_object = sorted(number_aces_for_object.items(), key=lambda v: v[1], reverse=True)

                inherit_index = 0
                if number_aces_for_object[inherit_index][0] != AceRight.EMPTY:
                    if number_aces_for_object[inherit_index][0] > 7 and \
                            len([vectors[vector_index][i] < 8 for vector_index in cluster]) != 0:
                        for tmp in number_aces_for_object:
                            if tmp[0] < 8:
                                inherit_index = number_aces_for_object.index(tmp)
                        if inherit_index > 0:
                            rights_list.append(Ace(self.objects[i], number_aces_for_object[inherit_index][0]))
                    else:
                        rights_list.append(Ace(self.objects[i], number_aces_for_object[inherit_index][0]))

            folder = ROOT_FOLDER + str(folder_number) + '/'
            os.mkdir(folder)
            folder_number += 1
            set_right(folder, rights_list)
            for file_index in cluster:
                os.rename(ROOT_FOLDER + self.files[file_index].name, folder + self.files[file_index].name)
                self.check_rights(self.files[file_index], folder)

    def check_rights(self, file: File, current_dir: str):
        sd = win32security.GetFileSecurity(os.path.join(current_dir, file.name),
                                           win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            raise len(file.rights_list) == 0
        else:
            users = defaultdict(list)
            for ace_no in range(0, dacl.GetAceCount()):
                ace = dacl.GetAce(ace_no)
                user_name = win32security.LookupAccountSid(None, ace[2])[0]
                if USER_SUBNAME in user_name:
                    users[user_name].append((ace[1], ace[0][0]))
            for user in users:
                all_rights = AceRight.EMPTY
                for right in users[user]:
                    all_rights += Ace.windows_ace_to_ace(*right)
                print(file.name, user, all_rights, str(users[user]), str(list(x.right for x in file.rights_list)))
                assert Ace(user, all_rights) in file.rights_list

    def result(self, clusters, vectors) -> float:
        ace_count = 0
        for cluster in clusters.values():
            for i in range(self.objects_count):
                number_aces_for_object = defaultdict(lambda: 0)
                for vector_index in cluster:
                    number_aces_for_object[vectors[vector_index][i]] += 1
                number_aces_for_object = sorted(number_aces_for_object.items(), key=lambda v: v[1], reverse=True)

                inherit_index = 0
                if number_aces_for_object[inherit_index][0] != AceRight.EMPTY:
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
            # delete conflicting allow right
            # example:
            # allow : 000101, deny : 110000
            # resulting: 110001 (111101 & (110000 + (~110)))
            #               ^-- need delete this     ^-- inverse deny
            denied = Test.generate_random_denied_right()
            return (0b111000 + Test.generate_random_allowed_right()) & \
                   (denied + ((~denied) >> 3))


def main():
    from test_config import test_config
    test = Test(config=test_config)
    test.start_test()


if __name__ == '__main__':
    main()
    # test_main()
