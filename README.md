# MOSEC-X-PLUGIN Backend

MOSEC-X-PLUGIN 后端检测API



## 关于我们

Website：https://security.immomo.com

WeChat:

<img src="https://momo-mmsrc.oss-cn-hangzhou.aliyuncs.com/img-1c96a083-7392-3b72-8aec-bad201a6abab.jpeg" width="200" hegiht="200" align="center" /><br>



## 版本要求

Python 3.7.x



## 安装

```shell script
> pip install -r requirements.txt
```



## 运行

```shell script
> python website.py
# will run on http://127.0.0.1:9000/
```



## 开发

#### 漏洞规则数据表

```sqlite
CREATE TABLE IF NOT EXISTS "vulrules" (
  "title" TEXT(255),                -- 漏洞标题
  "name" TEXT(255),                 -- 漏洞组件名称 ( vendor / groupId:artifactId )
  "severity" TEXT(10),              -- 漏洞危害等级 ( High / Medium / Low )
  "type" TEXT(10),                  -- 构建工具类型 ( Maven / pip / npm / Composer )
  "cve" TEXT(20),                   -- 漏洞对应CVE编号
  "cvss3" TEXT(10),                 -- 漏洞对应CVSS3分数
  "vul_version_fr" TEXT(255),       -- 漏洞组件最低版本 ( vul_version_fr <= 使用的组件版本 )
  "vul_version_to" TEXT(255),       -- 漏洞组件最高版本 ( 使用的组件版本 <= vul_version_to )
  "target_version" TEXT(255)        -- 漏洞组件安全版本 ( 数据类型是json.dumps(list) )
);
```

#### 检测流程

![flow](https://github.com/momosecurity/mosec-x-plugin-backend/blob/master/static/mosec-x-plugin-backend.svg)

###  API

#### POST /api/plugin

```json
{
    "type": "Maven",
    "language": "java",
    "severityLevel": "High",
    "name": "name1",
    "version": "version1",
    "from": [
        "name1@version1"
    ],
    "dependencies": {
        "name2": {
            "name": "name2",
            "version": "version2",
            "from": [
                "name1@version1",
                "name2@version2"
            ],
            "dependencies": {
                "name4": {
                    "name": "name4",
                    "version": "version4",
                    "from": [
                        "name1@version1",
                        "name2@version2",
                        "name4@version4"
                    ],
                    "dependencies": {}
                }
            }
        },
        "name3": {
            "name": "name3",
            "version": "version3",
            "from": [
                "name1@version1",
                "name3@version3"
            ],
            "dependencies": {}
        }
    }
}
```

#### Response

```json
{
    "ok": false,
    "dependencyCount": 2,
    "vulnerabilities": [
        {
            "title": "title",
            "severity": "High",
            "packageName": "name2",
            "version": "version2",
            "from": [
                "name1@version1",
                "name2@version2"
            ],
            "cve": "cve",
            "target_version": [
                "version2.1",
                "version3.0"
            ]
        }
    ]
}
```
