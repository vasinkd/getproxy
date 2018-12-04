# getproxy

[![Build Status](https://travis-ci.org/fate0/getproxy.svg?branch=master)](https://travis-ci.org/fate0/getproxy)
[![Updates](https://pyup.io/repos/github/fate0/getproxy/shield.svg)](https://pyup.io/repos/github/fate0/getproxy/)
[![PyPI](https://img.shields.io/pypi/v/getproxy.svg)](https://pypi.python.org/pypi/getproxy)
[![PyPI](https://img.shields.io/pypi/pyversions/getproxy.svg)](https://pypi.python.org/pypi/getproxy)

This branch replaces gevent with threading. That's why it is much easier to use as a part of other projects: you do not have to deal with monkey patching.

getproxy 是一个抓取发放代理网站，获取 http/https 代理的程序，
每 15 min 会更新数据至 [fate0/proxylist](https://github.com/fate0/proxylist)


## 1. 安装

```
pip install -U getproxy
```

## 2. 使用

### 帮助信息
```
➜  ~ getproxy --help
Usage: getproxy [OPTIONS]

Options:
  --in-proxy TEXT   Input proxy file
  --out-proxy TEXT  Output proxy file
  --help            Show this message and exit.
```

* `--in-proxy` 可选参数，待验证的 proxies 列表文件
* `--out-proxy` 可选参数，输出已验证的 proxies 列表文件，如果为空，则直接输出到终端

`--in-proxy` 文件格式和 `--out-proxy` 文件格式一致

### 使用例子

```
(test2.7) ➜  ~ getproxy
INFO:getproxy.getproxy:[*] Init
INFO:getproxy.getproxy:[*] Current Ip Address: 1.1.1.1
INFO:getproxy.getproxy:[*] Load input proxies
INFO:getproxy.getproxy:[*] Validate input proxies
INFO:getproxy.getproxy:[*] Load plugins
INFO:getproxy.getproxy:[*] Grab proxies
INFO:getproxy.getproxy:[*] Validate web proxies
INFO:getproxy.getproxy:[*] Check 6666 proxies, Got 666 valid proxies

...
```


## 3. 输入/返回格式

每一行结果都是一个 json 字符串，格式如下:
```json
{
    "type": "http",
    "host": "1.1.1.1",
    "port": 8080,
    "anonymity": "transparent",
    "country": "CN",
    "response_time": 3.14,
    "from": "txt"
}
```

| 属性           | 类型    | 描述           | 可选值   |
|-------        |--------|--------        |----------|
| type          | str    | proxy 类型     | `http`, `https`|
| host          | str    | proxy 地址     |                       |
| port          | int    | 端口           |                       |
| anonymity     | str    | 匿名性         | `transparent`, `anonymous`, `high_anonymous` |
| country       | str    | proxy 国家     |               |
| response_time | float  | 响应时间        |                |
| from          | str    | 来源           |               |


## 4. Plugin 相关

### Plugin 代码格式

``` python

class Proxy(object):
    def __init__(self):
        self.result = []
        self.proxies = []

    def start(self):
        pass
```

### Plugin 返回结果

```
{
    "host": "1.1.1.1",
    "port": 8080,
    "from": "plugin name"
}
```

### Plugin 小提示

* 不要在 plugin 内使用多线程、gevent 等方法
* 如果目标网站存在分页，请在获取每页内容之后，自行添加 delay
* 如果目标网站存在分页，请在获取每页结果之后，及时放入 `self.result` 中
* 如果被目标网站 ban 了，可以利用已经验证的 proxies (也就是 `self.proxies`)

## 5. 第三方程序调用

直接运行 `getproxy` 等同于执行下面程序:

``` python
#! /usr/bin/env python
# -*- coding: utf-8 -*-

from getproxy import GetProxy

g = GetProxy()

# 1. 初始化，必须步骤
g.init()

# 2. 加载 input proxies 列表
g.load_input_proxies()

# 3. 验证 input proxies 列表
g.validate_input_proxies()

# 4. 加载 plugin
g.load_plugins()

# 5. 抓取 web proxies 列表
g.grab_web_proxies()

# 6. 验证 web proxies 列表
g.validate_web_proxies()

# 7. 保存当前所有已验证的 proxies 列表
g.save_proxies()

```

如果只想验证 proxies 列表，并不需要抓取别人的 proxies，则可以:

``` python
g.init()
g.load_input_proxies()
g.validate_input_proxies()

print(g.valid_proxies)
```

如果当前程序不需要输出 proxies 列表，而是在程序中直接使用，则可以:

``` python
g.init()
g.load_plugins()
g.grab_web_proxies()
g.validate_web_proxies()

print(g.valid_proxies)
```

## 6. Q & A

* 为什么不使用 xxx 数据库？

数据量并不大，就算用文本格式全读进内存，也占用不了多少内存，就算真的需要存储至数据库，自己再多写几行代码就搞定。
另外使用文本格式还有另外一个好处是可以创建这个项目 [fate0/proxylist](https://github.com/fate0/proxylist)

* 和 xxx 有什么区别?

简单、方便、快捷，除了 Python 环境，其他都不用设置。

* 报错啦，怎么办?

仔细看看错误信息，是不是一些 plugin 报错误，而且错误都是和网络相关的？
如果是的话，可能这些 plugin 访问的网站由于众所周知的原因被 block 了。
如果不是，赶紧提 Issue。

* 还继续添加新的 plugin 吗？

主要看这个项目 [fate0/proxylist](https://github.com/fate0/proxylist) 中的 `proxy.list` 数量，
如果 `proxy.list` 行数接近 5000 个，那就不再继续添加新的 plugin，防止 travis 15min 内不结束。
