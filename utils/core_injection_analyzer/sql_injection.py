import logging
from rich.logging import RichHandler


class SQL_injection_analyzer:
    def __init__(self) -> None:
        # table_name, {key_name : injection_index}
        self.dbs_data: dict[str, dict[str, dict[int, list[int]]]] = {}

    def sql_injection_payload_extract(self, payload: str) -> tuple[str, str, int, str, int]:
        # 1%' AND SUBSTR((SELECT COALESCE(totpSecret,CHAR(32)) FROM Users WHERE id=1 LIMIT 0,1),25,1)>CHAR(57) AND 'rbHn%'='rbHn
        head_index = payload.index("(")
        tail_index = len(payload) - payload[::-1].index(")") + 1

        payload = payload[head_index:tail_index]
        # ((SELECT COALESCE(totpSecret,CHAR(32)) FROM Users WHERE id=1 LIMIT 0,1),25,1)>CHAR(57)
        # logging.debug(f"Overall payload:\n{payload}")

        brackets_deepth = 0
        brackets_left = 0
        brackets_right = 0
        brackets_index = []
        for index, letter in enumerate(payload):
            if letter == "(":
                if brackets_deepth == 0:
                    brackets_left = index
                brackets_deepth += 1
            elif letter == ")":
                brackets_deepth -= 1
                if brackets_deepth == 0:
                    brackets_right = index + 1
                    brackets_index.append((brackets_left, brackets_right))
                    brackets_left = 0
                    brackets_right = 0
        # logging.debug(f"brackets index: {brackets_index}")
        payload_extract = payload[brackets_index[0][0] : brackets_index[0][1]]
        for i in ["(", ")", ","]:
            payload_extract = payload_extract.replace(i, " ")
        payload_extract = [i for i in payload_extract.split(" ") if i != ""]
        table_name = payload_extract[6]
        key_name = payload_extract[2]
        injection_index = payload_extract[12]
        compare_ascii = payload[brackets_index[1][0] : brackets_index[1][1]][1:-1]
        operator = payload[brackets_index[0][1]]
        return table_name, key_name, int(injection_index), operator, int(compare_ascii)

    def sql_injection_data_extract(self, injection_payload: tuple[str, str, int, str, int]):
        table_name, key_name, injection_index, operator, compare_ascii = injection_payload
        if operator == ">":
            compare_ascii += 1
            if table_name in self.dbs_data.keys():
                if key_name in self.dbs_data[table_name].keys():
                    if injection_index not in self.dbs_data[table_name][key_name].keys():
                        self.dbs_data[table_name][key_name][injection_index] = [compare_ascii]
                    else:
                        self.dbs_data[table_name][key_name][injection_index].append(compare_ascii)
                else:
                    self.dbs_data[table_name][key_name] = {injection_index: [compare_ascii]}
            else:
                self.dbs_data[table_name] = {key_name: {injection_index: [compare_ascii]}}

    def sql_injection_data_read(self):
        res_dbs_data = dict(self.dbs_data)
        for table_name in self.dbs_data.keys():
            for key_name in self.dbs_data[table_name].keys():
                for injection_index in self.dbs_data[table_name][key_name].keys():
                    res_dbs_data[table_name][key_name][injection_index]=[max(self.dbs_data[table_name][key_name][injection_index])]
        return res_dbs_data