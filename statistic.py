import sys
import pandas as pd
import numpy as np
from os.path import dirname, abspath
import pymysql


PROJECT_DIR = dirname(dirname(abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)

conn = pymysql.connect(
    host='localhost',
    user='root',
    password='123456',
    db='db1',
    charset='utf8mb4',
)


def main_behaivours():
    corsor = conn.cursor()
    corsor.execute('''select d.event_hash,d.src_ip, d.add_time_int, d.add_time, d.flow_size, c.app_behaviour from
        (sensitive_data_details as d)
        left join (
            select a.rule_id as rule_id, b.app_behaviour from (
                (select * from rule_sig_map) as a
                    right join app_name_behaviour as b
                    on a.sig_msg=b.behaviour_id)
            ) as c
        on d.rule_id=c.rule_id;
        ''')
    conn.close()
    df = pd.DataFrame(np.array(corsor.fetchall()), columns=["id", "src_ip", "ShiDuan", "dt", "wj", "XW"])
    return df

data = main_behaivours()


# 找到所有的单条记录src_ip
def find_all_src_ip():
    corsor = conn.cursor()
    corsor.execute('''select src_ip, count(src_ip) from sensitive_data_details group by src_ip''')
    df = pd.DataFrame(np.array(corsor.fetchall()), columns=["src_ip", "JiShu"])
    conn.close()
    return df['src_ip']


# 生成一个单条记录的总记录
def set_sigle_item(src_ip):
    return data[data['src_ip'] == src_ip]


# 当前表格总共有多少种收发行为
def find_all_behaviour():
    corsor = conn.cursor()
    corsor.execute('''select * from app_name_behaviour;''')
    df = pd.DataFrame(np.array(corsor.fetchall()), columns=["app_id", "XW", "id"])
    xw_height = []
    array2 = np.array(df)
    for i in range(len(df)):
        xw1 = array2[i][1]
        length = len(xw1.split("发送")) + len(xw1.split("外发"))
        height = [10 if length > 2 else 0][0]
        xw_height.append(height)
    df["xw_height"] = xw_height
    conn.close()
    return df
xw = find_all_behaviour()


# 单个用户每个时段的收发数据的大小
def sigle_sd_data(src_ip):
    corsor = conn.cursor()
    corsor.execute('''
        select  f.sd, sum(f.flow_size) , count(sd) from (
            select * from (
                select d.event_hash,d.src_ip, (100*d.add_time_int+hour(d.add_time)) as sd,
                                d.add_time, d.flow_size, c.app_behaviour from
                    (sensitive_data_details as d)
                left join (
                    select a.rule_id as rule_id, b.app_behaviour from (
                        (select * from rule_sig_map) as a
                            left join app_name_behaviour as b
                            on a.sig_msg=b.behaviour_id)
                    ) as c
                on d.rule_id=c.rule_id
                ) as e where e.src_ip=%s
            ) as f
        group by f.sd''', src_ip)
    df = pd.DataFrame(np.array(corsor.fetchall()), columns=["ShiDuan", "wjdx", "js"])
    df["src_ip"] = [src_ip for i in range(len(df))]
    conn.close()
    return df


def test():
    return pd.concat([sigle_sd_data(x) for x in find_all_src_ip()])


# 单个用户每个日期的收发数据的大小, 频率
def sigle_rq_data(src_ip):
    corsor = conn.cursor()
    corsor.execute('''
        select  f.sd, sum(f.flow_size) , count(sd) from (
            select * from (select d.event_hash,d.src_ip,
                    d.add_time_int as sd, d.add_time, d.flow_size, c.app_behaviour from
                (sensitive_data_details as d)
                left join (
                    select a.rule_id as rule_id, b.app_behaviour from (
                        (select * from rule_sig_map) as a
                            right join app_name_behaviour as b
                            on a.sig_msg=b.behaviour_id)
                    ) as c
                on d.rule_id=c.rule_id
                ) as e where e.src_ip=%s
            ) as f
        group by f.sd''', src_ip)
    df = pd.DataFrame(np.array(corsor.fetchall()), columns=["ShiDuan", "wjdx", "sl"])
    df["src_ip"] = [src_ip for i in range(len(df))]
    conn.close()
    return df


# 对应每个用户在数据库中的活跃天数
def days(src_ip):
    corsor = conn.cursor()
    corsor.execute('''select add_time_int from sensitive_data_details where src_ip=%s group by add_time_int ''', src_ip)
    df = pd.DataFrame(np.array(corsor.fetchall()), columns=["date"])
    conn.close()
    return df


# 单个用户每天的平均发送文件数量
def data_extract_plv(src_ip):
    sigle_data = sigle_rq_data(src_ip)
    return sum(sigle_data["sl"])/len(days(src_ip))


# 时间段权重_时间段字段主函数
def data_extract_sd(src_ip):
    sd_height = [10 if i <= 9 or i >= 18 else 5 if i >= 12 & i <= 14 else 0 for i in range(24)]
    gaim = sigle_sd_data(src_ip)
    gaim["sd_height"] = [sd_height[gaim["ShiDuan"].values[i] % 100] for i in range(len(gaim))]
    # 直接产生权重和
    sum_height = sum(gaim["sd_height"])
    return sum_height


# 抽离单个人员的行为频率_特征
def extract_plv(src_ip):
    # 单个人员平均每天的敏感操作的数量
    data_extract_plv(src_ip)


# 抽离单个人员的外联时间_特征
def extract_time_temp(src_ip):
    # 返回时段综合权重和
    return data_extract_sd(src_ip)


# 抽离单个人员外联方式——特征 50
def extract_app_height(srp_ip):
    sigle_df = data[data['src_ip'] == srp_ip]
    # pd.merge(df1, df2, on='key', how='left')
    df = pd.merge(sigle_df, xw, on="XW", how='left')
    temp = df[df['xw_height'] == 10]
    xw_count = np.unique(temp['XW'])
    return temp, len(xw_count)
    # 单个人员的敏感数量
    # print(extract_app_height(find_all_src_ip()[2])[1])


def set_single_info(src_ip):
    info = {}
    info.setdefault("用户", src_ip)
    info.setdefault("外联频率", data_extract_plv(src_ip))
    info.setdefault("外联方式", extract_app_height(src_ip)[1])
    info.setdefault("外联时间", extract_time_temp(src_ip))

    return info


def main():
    array = [set_single_info(x) for x in find_all_src_ip()]
    df = pd.DataFrame(array, columns=["外联频率", "外联方式", "外联时间"])
    return df


def min_max_data(arr1):
    alfa = 0.05
    # 标准化数据
    max1 = np.max(arr1) * (1+alfa)
    min1 = np.min(arr1) * (1-alfa)
    res = [(x - min1)/(max1-min1) for x in arr1]
    return res


def main2():
    array = [set_single_info(x) for x in find_all_src_ip()]
    df = pd.DataFrame(array, columns=["用户", "外联频率", "外联方式", "外联时间"])
    res = pd.DataFrame()
    res["用户"] = df["用户"]
    res["外联频率"] = [250 * x for x in min_max_data(np.array(df["外联频率"]))]
    res["外联方式"] = [50 * x for x in min_max_data(np.array(df["外联方式"]))]
    res["外联时间"] = [250 * x for x in min_max_data(np.array(df["外联时间"]))]

    return res


def js_you_want():
    return main2().to_dict()


def write_to_db():
    corsor = conn.cursor()
    corsor.execute('''  ''')

    conn.close()


