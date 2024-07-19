# CVE_Montior
自动收集目前已知的CVE及其对应Poc，并可交由LLM进行分析和拆解攻击步骤，生成SOP，自动生成模拟该漏洞的蜜罐脚本。
本项目处于初步阶段，有许多纰漏之处，欢迎指教。

数据来源于[cvelistV5](https://github.com/CVEProject/cvelistV5 "cvelistV5")以及[Poc-in-Github](https://github.com/nomi-sec/PoC-in-GitHub "Poc-in-Github")。

## 快速开始
1.克隆本仓库
```bash
git clone https://github.com/ABSllk/CVE_Montior.git
```

2.安装依赖库
```bash
pip install requirements.txt
```

3.部署漏洞库
```bash
python CVE_Montior.py -u
```

## 参数用法
-u  更新或部署漏洞库

-s \<CVE\> 搜索漏洞

-a \<CVE\> 使用LLM分析漏洞

-p \<PATH\> 指定漏洞库路径,不指定默认为当前路径/上一次使用路径

-P \<CVE\> \<Poc\> 下载某漏洞的Poc，接受两个参数，第一个为CVE编号，第二个为Poc序号（可由-s获取）

-S \<CVE\> 自动生成某漏洞的标准操作程序（SOP）

-H \<CVE\> 自动生成模拟某漏洞的蜜罐脚本

使用有关LLM的功能前需在config.json中配置api_key，可使用openai第三方代理，目前仅支持Chatgpt


