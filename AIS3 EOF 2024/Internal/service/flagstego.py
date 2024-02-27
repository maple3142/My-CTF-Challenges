from string import ascii_lowercase
import random
import re
import sys

class GenL33tFlag:
    #SECRET_KEY = b"s3cr3t_k3y"
    def __init__(self, secret_key, original_flag, flag_prefix="AIS3"):
        SECRET_KEY = secret_key
        random.seed(SECRET_KEY)
        self.uid_mapping = list(range(1024))
        random.shuffle(self.uid_mapping)
        self.reverse_uid_mapping = {v: k for k, v in enumerate(self.uid_mapping)}
        flag_len = len(original_flag)
        self.subsitution_order_all = list(range(flag_len))
        random.shuffle(self.subsitution_order_all)
        random.seed()
        self.original_flag = original_flag
        self.flag_prefix = flag_prefix

        self.mapping = {
            "a": ['a', '@', 'A', '4'],
            "b": ['B', '8', 'b'],
            "c": ['c', 'C'],
            "d": ['D', 'd'],
            'e': ['e', '3', 'E'],
            'f': ['F', 'f'],
            'g': ['9', 'g', 'G'],
            'h': ['H', 'h'],
            'i': ['1', 'I', 'i'],
            'j': ['j', 'J'],
            'k': ['K', 'k'],
            'l': ['L', 'l'],
            'm': ['m', 'M'],
            'n': ['n', 'N'],
            'o': ['0', 'O', 'o'],
            'p': ['P', 'p'],
            'q': ['q', 'Q'],
            'r': ['R', 'r'],
            's': ['S', '5', '$', 's'],
            't': ['T', 't', '7'],
            'u': ['U', 'u'],
            'v': ['V', 'v'],
            'w': ['w', 'W'],
            'x': ['X', 'x'],
            'y': ['Y', 'y'],
            'z': ['2', 'z', 'Z']
        }
        # reverse mapping
        self.reverse_mapping = {}
        for k, v in self.mapping.items():
            for i, c in enumerate(v):
                self.reverse_mapping[c] = i
        #print(self.reverse_mapping)
        
        if not (len([*filter(lambda x: x in ascii_lowercase, original_flag)]) >= 10):
            raise ValueError("flag should have at least 10 alphabets")
        if not (all([c not in self.reverse_mapping for c in original_flag if c not in ascii_lowercase])):
            raise ValueError("flag should not contain l33t characters (@, $, 1, 2, 3, 4, 5, 7, 8, 9, 0)")

        self.subsitution_order = []
        for i in self.subsitution_order_all:
            c = original_flag[i]
            if c not in self.mapping:
                continue
            self.subsitution_order.append(i)
        subsitutitable_len = len(self.subsitution_order)
        dynamic_bytes = subsitutitable_len-((subsitutitable_len-10)//2)
        self.subsitution_order = self.subsitution_order[:dynamic_bytes]
        
        random.seed(SECRET_KEY)
        static_subsitute_flag = [c for c in self.original_flag]
        for i,c in enumerate(self.original_flag):
            if i not in self.subsitution_order and c in self.mapping:
                static_subsitute_flag[i] = random.choice(self.mapping[c])
        self.original_flag = "".join(static_subsitute_flag)

        regex = self.regex()
        #print(regex)
        #print(self.subsitution_order)
        for i in range(1024):
            flag = self.stego(i)
            #print(i, flag, self.destego(flag))
            if i != self.destego(flag):
                raise ValueError("flag couldn't be destego correctly.")
            if not re.match(regex, flag):
                raise ValueError("flag doesn't match generated regex.")

    def flag_unwrap(self, flag: str) -> str:
        match = re.fullmatch("^"+self.flag_prefix+"\{(.*)\}$", flag)
        if match is None:
            return flag
        #print(match[1])
        return match[1]
        
    def stego(self, uid: int, prepend_prefix=False) -> str:
        orig_str = self.original_flag

        uid = self.uid_mapping[uid]
        #print(uid)
        bin_data = bin(uid)[2:].zfill(10)
        encoded = [c for c in orig_str]
        n = 0
        #for i, c in enumerate(orig_str):
        for i in self.subsitution_order:
            c = orig_str[i]
            if n == 10: break
            if c not in self.mapping:
                #encoded += c
                continue
            #encoded += self.mapping[c][int(bin_data[n])]
            encoded[i] = self.mapping[c][int(bin_data[n])]
            #print(i, c, int(bin_data[n]), encoded[i])
            n += 1

        random.seed(uid)
        #for i in range(i, len(orig_str)):
        for i in self.subsitution_order[n:]:
            if orig_str[i] not in self.mapping:
                #encoded += orig_str[i]
                continue
            #encoded += random.choice(self.mapping[orig_str[i]])
            encoded[i] = random.choice(self.mapping[orig_str[i]])
            #print(i, orig_str[i], encoded[i])
        stegoed_flag = "".join(encoded)
        if prepend_prefix:
            return self.flag_prefix+"{"+stegoed_flag+"}"
        return stegoed_flag

    def destego(self, encoded: str) -> int:
        encoded = self.flag_unwrap(encoded)
        decoded = ''
        #encoded = list(filter(lambda x: x in self.reverse_mapping, encoded))[:10]
        #for c in encoded:
        n = 0
        for i in self.subsitution_order:
            if n==10:
                break
            c = encoded[i]
            if c not in self.reverse_mapping:
                continue
            n += 1
            decoded += str(self.reverse_mapping[c])
            #print(c, str(self.reverse_mapping[c]))
        
        return self.reverse_uid_mapping[int(decoded, 2)]

    def regex(self, prepend_prefix=False) -> str:
        regex = ''
        for i,c in enumerate(self.original_flag):
            if c in self.mapping and i in self.subsitution_order:
                regex += '[' + ''.join(self.mapping[c]) + ']'
            else:
                regex += re.escape(c)
        if prepend_prefix:
            return self.flag_prefix+"\{"+regex+"\}"
        return regex
    # ORIG_FLAG = "~~baby welcome challenge owo!~~"



if __name__ == "__main__":
    #flag_gen = GenL33tFlag(b"s3cr3t_k3y", "just_easy_command_injection")
    flag_gen = GenL33tFlag(b"s3cr3t_k3y", "using_windows_is_such_a_pain....")
    #print(flag_gen.flag_unwrap("AIS3{this_is_aisss_eof_stego_flag}"))
    #print(flag_gen.regex())
    #for i in range(592,900):
    #    print(flag_gen.stego(i))
    #print(flag_gen.regex(True))
    #print(flag_gen.destego("AIS3{jU5T_3a$Y_c0mm4Nd_InJEc7ION}"))
    #print(flag_gen.stego(190))
    #print(flag_gen.stego(128))
    #print(flag_gen.destego("AIS3{JU$T_3@5Y_comm@Nd_1Njec710N}"))
    print(flag_gen.destego("AIS3{Us1ng_w1nd0wS_I$sucH@_P@1N....}"))