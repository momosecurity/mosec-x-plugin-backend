# MOSEC-X-PLUGIN Backend

MOSEC-X-PLUGIN 后端API服务

## 关于我们

Website：https://security.immomo.com

WeChat:

<img src="https://momo-mmsrc.oss-cn-hangzhou.aliyuncs.com/img-1c96a083-7392-3b72-8aec-bad201a6abab.jpeg" width="200" hegiht="200" align="left" />

## 版本要求

Python 3.7.x

## 安装

```shell script
> pip install -r requirements.txt
```

## 运行

```shell script
# will run on http://127.0.0.1:9000/

> python website.py
```

## API

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