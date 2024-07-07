import os
import subprocess
import json
import requests
import argparse
import openai

#克隆仓库
def clone(url, path):
    cmd = ['git', 'clone', url, path]
    subprocess.run(cmd, cwd=path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print('Clone Success')

#更新仓库
def fetch(path):
    cmd = ['git', 'fetch']
    subprocess.run(cmd, cwd=path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print('Fetch Success')

#拉取仓库
def pull(path):
    cmd = ['git', 'pull']
    subprocess.run(cmd, cwd=path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print('Pull Success')

#和最新仓库比较，判断新增了哪些CVE
def compare(path, remote_hash, local_hash):
    #比较两个commit
    cmd = ['git', 'diff', '--name-status', local_hash, remote_hash]
    diff = subprocess.run(cmd, cwd=path, capture_output=True, text=True).stdout.strip()
    #过滤出状态为A的文件
    added = []
    for line in diff.split('\n'):
        if line.startswith('A'):
            added.append(line.split('\t')[1])
    return added

#获取提交hash
def get_commit_hash(path, branch):
    cmd = ['git', 'rev-parse', branch]
    commit_hash = subprocess.run(cmd, cwd=path, capture_output=True, text=True).stdout.strip()
    return commit_hash

#获取CVE列表
def get_cve_list(path):
    print('Getting CVE list...')
    url = 'https://github.com/CVEProject/cvelistV5.git'
    path = path+r'\cvelistV5'
    if not os.path.exists(path):
        clone(url, path)
    else:
        # 更新仓库信息
        fetch(path)
        # 获取远程仓库的最新commit hash
        remote_hash = get_commit_hash(path, 'origin/main')
        # 获取本地仓库的commit hash
        local_hash = get_commit_hash(path, 'HEAD')
        #如果两个hash相同，说明没有新的commit
        if local_hash == remote_hash:
            print('The repository is up to date')
        else:
            print('The repository is behind')
            added = compare(path,remote_hash,local_hash)
            if added:
                print('New CVEs:')
                for cve in added:
                    print(extract_cve(cve))
            else:
                print('No new CVEs')
            pull(path)

#获取PoC列表
def get_poc_list(path):
    print('Getting PoC list...')
    url = 'https://github.com/nomi-sec/PoC-in-GitHub.git'
    path = path+r'\PoC-in-GitHub'
    if not os.path.exists(path):
        clone(url, path)
    else:
        # 更新仓库信息
        fetch(path)
        # 获取远程仓库的最新commit hash
        remote_hash = get_commit_hash(path, 'origin/master')
        # 获取本地仓库的commit hash
        local_hash = get_commit_hash(path, 'HEAD')
        #如果两个hash相同，说明没有新的commit
        if local_hash == remote_hash:
            print('The repository is up to date')
        else:
            print('The repository is behind')
            added = compare(path,remote_hash,local_hash)
            if added:
                print('New PoCs:')
                for poc in added:
                    print(extract_cve(poc))
            else:
                print('No new PoCs')
            pull(path)

#从路径中提取CVE编号
def extract_cve(path):
    cve = path.split('/')[-1].replace('.json','')
    return cve

#给出CVE编号，搜索CVE信息和POC
def search(search_word,path):
    print('Searching...')
    cve_path = path+r'\cvelistV5'
    #CVE搜索
    cve_file = []
    for root, dirs, files in os.walk(cve_path):
        for file in files:
            if search_word in file:
                cve_file.append(file.replace('.json',''))
    if cve_file:
        #输出搜索到的CVE列表，让用户选择
        print('Search results:')
        for i in range(len(cve_file)):
            print(f'{i}. {cve_file[i]}')
        choice = int(input('Please select the CVE you want to search: '))
        if choice < len(cve_file):
            get_cve_info(cve_file[choice],path)
        else:
            print('Invalid input')
    else:
        print('No CVE found')

#获取CVE信息
def get_cve_info(cve,path):
    code,title,description,score = analyze_cve_json(cve,path)
    if code == '':
        print('No CVE information found')
        return
    print(f"编号: {code}")
    print(f"标题: {title}")
    print(f"描述: {description}")
    print("评分:")
    for item in score:
        print(item)
    #读取PoC信息
    num,poc_list = analyze_poc_json(cve,path)
    if num>0:
        print(f"PoC数量: {num}")
        print("PoC列表(按star数排序):")
        if num>5:
            for i in range(5):
                print(poc_list[i])
            choice = input("Do you want to see more PoCs? (y/n)")
            if choice == 'y':
                for i in range(5,num):
                    print(poc_list[i])
        else:
            for i in range(num):
                print(poc_list[i])
    else:
        print("No PoC found")
    
def analyze_cve_json(cve,path):
    cve_path = path+r'\cvelistV5'
    #提取CVE编号中的年份和编号
    year = cve.split('-')[1]
    code = (cve.split('-')[2])[:-3]+'xxx'
    #读取CVE信息
    cve_info_path = cve_path+"\\cves\\"+year+"\\"+code+"\\"+cve+".json"
    if not os.path.exists(cve_info_path):
        return '','','',''
    with open(cve_info_path,'r',encoding='utf-8') as f:
        cve_info = f.read()
    data=json.loads(cve_info)
    code=data['cveMetadata']['cveId']
    title=data['containers']['cna']['title']
    description=data['containers']['cna']['descriptions'][0]['value']
    score=[]
    for item in data['containers']['cna']['metrics']:
        key = list(item.keys())[0]
        if key in ['cvssV3_1', 'cvssV3_0']:
            score.append(f"{key}: Score:{item[key]['baseScore']} Severity:{item[key]['baseSeverity']}")
    return code,title,description,score

def analyze_poc_json(cve,path):
    poc_path = path+r'\PoC-in-GitHub'
    #提取CVE编号中的年份
    year = cve.split('-')[1]
    poc_info_path = poc_path+"\\"+year+"\\"+cve+".json"
    if os.path.exists(poc_info_path):
        with open(poc_info_path,'r',encoding='utf-8') as f:
            poc_info = f.read()
        data=json.loads(poc_info)
        num = len(data)
        poc_list=[]
        #按star数排序
        data.sort(key=lambda x:x['stargazers_count'],reverse=True)
        for i in range(num):
            poc_list.append(f"{i+1}. {data[i]['name']}  URL：{data[i]['html_url']}")
        return num,poc_list
    else:
        return 0,[]

#使用chatgpt判断该CVE是否有被利用的价值
def llm_analyze_cve(cve):
    with open('config.json','r') as f:
        api_key = config['api_key']
        if config['api_base'] == '':
            api_base = 'https://api.openai.com'
        else:
            api_base = config['api_base']
    client = openai.Client(api_key=api_key, base_url=api_base)
    prompt = "You will then receive a description of a vulnerability.Determine if the vulnerability is exploitable, as defined by the following: 1.The vulnerability is in widely used infrastructure services and frameworks, such as Operating system vulnerabilities,HTTP server (Apache, Nginx, etc.) vulnerabilities, database services vulnerabilities, virtualization and container vulnerabilities, password management and authentication services vulnerabilities. But not in specific applications.2 Can be exploited remotely 3. This vulnerability can have serious consequences. If the above three points are met, it is considered valuable; otherwise, it is not. If there is value, please give possible attack steps to help prevent, if not, please say there is no exploit value, don't need to output any other information. "
    code,title,description,score = analyze_cve_json(cve,path)
    if code == '':
        return 'No CVE information found'
    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": description}
    ]
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages
        )
        #print(response)
        return response.choices[0].message.content
    except Exception as e:
        print(e)
        return 0

def init():
    global config
    try:
        with open('config.json','r') as f:
            config = json.load(f)
    except:
        config = {'path':'\\','api_key':'','api_base':''}
        with open('config.json','w') as f:
            json.dump(config,f)

if __name__ == '__main__':
    init()
    #get_cve_list(path)
    #get_poc_list(path)
    #search('CVE-2024-2333',path)
    parser = argparse.ArgumentParser(description='CVE Monitor')
    parser.add_argument('-s', '--search', help='Search for CVE information')
    parser.add_argument('-p', '--path', help='Specify the path of the repository')
    parser.add_argument('-u', '--update', action='store_true',help='Update the CVE and PoC list')
    parser.add_argument('-a', '--analyze', help='Analyze the CVE by LLM model')
    args = parser.parse_args()
    if args.path:
        path = args.path
        config['path'] = path.replace('\\','\\\\')
        with open('config.json','w') as f:
            json.dump(config,f)
    else:
        #从配置文件中读取路径
        try:
            path = config['path'].replace('\\\\','\\')
        except:
            print('Please specify the path of the repository')
            exit()
    if args.update:
        get_cve_list(path)
        get_poc_list(path)
    if args.search:
        search(args.search,path)
    if args.analyze:
        print(llm_analyze_cve(args.analyze))