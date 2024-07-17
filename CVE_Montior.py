import os
import subprocess
import json
import hashlib
import argparse
import openai

#克隆仓库
def clone(url, path):
    #如果路径已存在，删除原有文件
    if os.path.exists(path):
        os.system(f'rd /s /q {path}')
    os.makedirs(path)
    cmd = ['git', 'clone', url, path]
    result=subprocess.run(cmd, cwd=path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise Exception(f'Failed to clone repository: {result.stderr.decode("utf-8")}')
    print('Clone Success')

#更新仓库
def fetch(path):
    cmd = ['git', 'fetch']
    result=subprocess.run(cmd, cwd=path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise Exception(f'Failed to fetch repository: {result.stderr.decode("utf-8")}')
    print('Fetch Success')

#拉取仓库
def pull(path):
    cmd = ['git', 'pull']
    result=subprocess.run(cmd, cwd=path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise Exception(f'Failed to pull repository: {result.stderr.decode("utf-8")}')
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

#获取文件hash
def get_hash(file):
    md5 = hashlib.md5()
    with open(file, 'rb') as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            md5.update(data)
    print(f"File{file} Hash:{md5.hexdigest()}")
    return md5.hexdigest()

#获取CVE列表
def get_cve_list(path):
    print('Getting CVE list...')
    url = 'https://github.com/CVEProject/cvelistV5.git'
    path = path+r'\cvelistV5'
    if not os.path.exists(path):
        try:
            clone(url, path)
        except Exception as e:
            print(e)
            return
    else:
        # 更新仓库信息
        try:
            fetch(path)
        except Exception as e:
            print(e)
            return
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
        try:
            clone(url, path)
        except Exception as e:
            print(e)
            return
    else:
        # 更新仓库信息
        try:
            fetch(path)
        except Exception as e:
            print(e)
            return
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

#从CVE编号中提取年份和编号
def extract_year(cve):
    year = cve.split('-')[1]
    code = cve.split('-')[2]
    return year,code

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
    print(f"CVE: {code}")
    print(f"Title: {title}")
    print(f"Description: {description}")
    print("Score:")
    for item in score:
        print(item)
    #读取PoC信息
    num,poc_list = analyze_poc_json(cve,path)
    if num>0:
        print(f"The num of PoC:{num}")
        print("PoC list (Sorted by star):")
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

def get_cve_path(cve,path):
    cve_path = path+r'\cvelistV5'
    #提取CVE编号中的年份和编号
    year,code = extract_year(cve)
    code = code[:-3]+'xxx'
    #读取CVE信息
    cve_info_path = cve_path+"\\cves\\"+year+"\\"+code+"\\"+cve+".json"
    if not os.path.exists(cve_info_path):
        cve_info_path = ''
    return cve_info_path

def analyze_cve_json(cve,path):
    cve_info_path = get_cve_path(cve,path)
    if cve_info_path=='':
        return '','','',''
    with open(cve_info_path,'r',encoding='utf-8') as f:
        cve_info = f.read()
    data=json.loads(cve_info)
    code = data['cveMetadata'].get('cveId', 'None')
    title = data['containers']['cna'].get('title', 'None')
    description = data['containers']['cna']['descriptions'][0].get('value', 'None')
    score=[]
    for item in data['containers']['cna'].get('metrics', ''):
        key = list(item.keys())[0]
        if key in ['cvssV3_1', 'cvssV3_0']:
            score.append(f"{key}: Score:{item[key]['baseScore']} Severity:{item[key]['baseSeverity']}")
    if not score:
        score.append('No score information')
    return code,title,description,score

def analyze_poc_json(cve,path):
    poc_path = path+r'\PoC-in-GitHub'
    #提取CVE编号中的年份
    year,code = extract_year(cve)
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
            poc_list.append(f"{i+1}. {data[i]['name']}  URL:{data[i]['html_url']}")
        return num,poc_list
    else:
        return 0,[]

#向Chatgpt发送请求
def chatgpt_request(cve,prompt,model='gpt-3.5-turbo',message=''):
    code,title,description,score = analyze_cve_json(cve,path)
    if code == '':
        return 'No CVE information found'
    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": f"code:{code}\ntitle:{title}\ndescription:{description}\n{message}"}
    ]
    api_key = config['api_key']
    api_base = config['api_base']
    client = openai.Client(api_key=api_key, base_url=api_base)
    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
        )
        #print(response)
        return response.choices[0].message.content
    except Exception as e:
        print(e)
        return 0

#向Chatgpt上传文件
def chatgpt_upload_file(file,model='gpt-3.5-turbo'):
    print("Uploading file...")
    api_key = config['api_key']
    api_base = config['api_base']
    client = openai.Client(api_key=api_key, base_url=api_base)
    try:
        response = client.files.create(file=open(file, 'rb'),purpose='assistant')
        return response.id
    except Exception as e:
        print(e)
        return 0

#使用chatgpt判断该CVE是否有被利用的价值
def llm_analyze_cve(cve):
    prompt = "You will then receive a description of a vulnerability.Determine if the vulnerability is exploitable, as defined by the following: 1.The vulnerability is in widely used infrastructure services and frameworks, such as Operating system vulnerabilities,HTTP server (Apache, Nginx, etc.) vulnerabilities, database services vulnerabilities, virtualization and container vulnerabilities, password management and authentication services vulnerabilities. But not in specific applications.2 Can be exploited remotely 3. This vulnerability can have serious consequences. If the above three points are met, it is considered valuable; otherwise, it is not. If there is value, please give a possible step-by-step attack, if not, please say there is no exploit value, don't need to output any other information. "
    response = chatgpt_request(cve,prompt)
    return response

#使用chatgpt自动生成某个CVE的SOP
def llm_generate_sop(cve):
    prompt = "接下来你将收到一个漏洞的信息，请使用中文给出处置这个漏洞的标准作业程序。内容⾄少包括：SOP基本信息，SOP的⽤途，SOP的⽬标⽤⼾技能要求，漏洞详细信息，漏洞处置⽅案（打补丁，升级，还是修改配置等），请提供更详细具体可操作的漏洞的修补步骤，需要包含具体命令。"
    response = chatgpt_request(cve,prompt)
    return response

#过滤出代码文件
def filter_code_file(path):
    code_file = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith('.py') or file.endswith('.c') or file.endswith('.cpp') or file.endswith('.java'):
                code_file.append(os.path.join(root, file))
    return code_file

#使用chatgpt自动生成某个CVE的蜜罐脚本 转发KEY不支持文件上传qwq
# def llm_generate_honeypot(cve,path):
#     prompt = "接下来你将收到一个漏洞的信息和几个与之对应的POC文件，请根据给出的信息写出一个自动化python脚本模拟该漏洞，要求：脚本可以监听服务对应的端口将自己模仿成一个正常的服务，不能输出该服务正常响应信息之外的任何信息，可以正确响应攻击者发送的请求，根据漏洞匹配对应攻击步骤，从而让攻击者在一系列步骤后认为自己成功利用了该漏洞，并且记录攻击者的行为。"
#     #克隆前三个PoC
#     message=''
#     cve_path = get_cve_path(cve,path)
#     if cve_path=='':
#         return 'No CVE information found'
#     file_id = chatgpt_upload_file(cve_path)
#     if file_id:
#         message += f"CVE File ID:{file_id}\n"
#     for i in range(3):
#         poc_path=get_poc([cve,i],path)
#         code_file = filter_code_file(poc_path)
#         for file in code_file:
#             file_id = chatgpt_upload_file(file)
#             if file_id:
#                 message += f"POC{i} File ID:{file_id}\n"
#     response = chatgpt_request(cve,prompt,message=message)
#     return response

def llm_generate_honeypot(cve,path):
    prompt = "接下来你将收到一个漏洞的信息和几个与之对应的POC代码，请根据给出的信息写出一个自动化python脚本模拟该漏洞，要求：脚本可以监听服务对应的端口将自己模仿成一个正常的服务，不能输出该服务正常响应信息之外的任何信息，可以正确响应攻击者发送的请求，根据漏洞匹配对应攻击步骤，从而让攻击者在一系列步骤后认为自己成功利用了该漏洞，并且记录攻击者的行为。"
    #克隆前三个不重复的PoC
    message=''
    i=1
    ponit=0
    map = {}
    while i<=3:
        t=0
        poc_path=get_poc([cve,ponit],path)
        code_file = filter_code_file(poc_path)
        for file in code_file:
            #计算文件Hash
            hash = get_hash(file)
            if hash not in map:
                map[hash]=1
                with open(file,'r',encoding='utf-8') as f:
                    code = f.read()
                message += f"POC{i} Code:{code}\n"
                t=1
        if t==1:
            i+=1
        ponit+=1
    response = chatgpt_request(cve,prompt,message=message,model='gpt-4o')
    return response

#克隆远程Poc仓库
def get_poc(param,path):
    cve = param[0]
    if len(param)>1:
        no = int(param[1])
    else:
        no = 0
    num,poc_list = analyze_poc_json(cve,path)
    if num == 0:
        print('No PoC found')
        return
    if no>=num:
        print('Invalid input')
        return
    url = poc_list[no].split('URL:')[1]+'.git'
    year,code = extract_year(cve)
    poc_path = path+'\\PoC\\'+year+'\\'+code+'\\'+str(no)+'\\'
    clone(url,poc_path)
    print('PoC downloaded')
    return poc_path

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
    parser.add_argument('-P', '--POC', help='Download PoC',nargs='+')
    parser.add_argument('-S', '--SOP', help='Use LLM model to generate SOP')
    parser.add_argument('-H', '--honeypot', help='Use LLM model to generate honeypot script')
    args = parser.parse_args()
    config = {}
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
    if args.POC:
        get_poc(args.POC,path)
    if args.SOP:
        print(llm_generate_sop(args.SOP))
    if args.honeypot:
        print(llm_generate_honeypot(args.honeypot,path))