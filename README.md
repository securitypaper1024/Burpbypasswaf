# Burpbypasswaf

<p align="center">
  <img src="https://img.shields.io/badge/Burp%20Suite-Extension-orange" alt="Burp Extension">
  <img src="https://img.shields.io/badge/Python-Jython%202.7-blue" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</p>

通过字符编码绕过WAF检测的 Burp Suite Python 扩展。利用 EBCDIC、UTF-16/32 等编码方式，绕过 WAF 对恶意请求的检测。

## 功能特性

- **12种编码支持**: IBM037, IBM500, IBM1026, UTF-16, UTF-32 等
- **完整请求编辑**: 可直接编辑完整HTTP请求
- **Fuzz All**: 一键生成所有编码变体
- **批量发送**: 发送选中或全部Fuzz请求
- **响应查看**: 完整显示请求和响应内容
- **右键菜单**: 从Repeater/Proxy等工具发送请求到面板

## 支持的编码

| 编码类型 | 编码名称 | 用途 |
|---------|---------|------|
| EBCDIC | IBM037, IBM500, IBM1026 | 古老的IBM编码，多数WAF无法识别 |
| Unicode | UTF-16, UTF-16BE, UTF-16LE | 宽字符编码绕过 |
| Unicode | UTF-32, UTF-32BE, UTF-32LE | 超宽字符编码绕过 |
| ISO | ISO-8859-1, ISO-8859-15 | Latin编码绕过 |
| Windows | Windows-1252 | Windows代码页绕过 |

## 安装方法

### 1. 安装 Jython

1. 下载 Jython Standalone JAR: https://www.jython.org/download
2. 推荐版本: `jython-standalone-2.7.3.jar`

### 2. 配置 Burp Suite

1. 打开 Burp Suite
2. 进入 `Extender` -> `Options`
3. 在 `Python Environment` 部分
4. 点击 `Select file...` 选择下载的 Jython JAR 文件
5. 等待加载完成

### 3. 加载扩展

1. 进入 `Extender` -> `Extensions`
2. 点击 `Add`
3. Extension type: **Python**
4. 选择 `waf_bypass_burp.py` 文件
5. 点击 `Next`

## 使用方法

### 方式1: 右键菜单（推荐）

1. 在 Proxy/Repeater 等工具中右键点击请求
2. 选择 `WAF Bypass Encoder` -> `Send Full Request to Panel (View Only)`
3. 切换到 `WAF Bypass Encoder` 标签页
4. 点击 `Parse & Extract` 解析请求体
5. 点击 `Fuzz All` 生成所有编码请求
6. 点击 `Send All Fuzz` 批量发送

### 方式2: 手动输入

1. 切换到 `WAF Bypass Encoder` 标签页
2. 在 `Full Request` 区域粘贴完整HTTP请求
3. 点击 `Parse & Extract` 解析请求
4. 设置目标主机和端口
5. 点击 `Fuzz All` -> `Send All Fuzz`

## 界面说明

### 控制面板
- **Target Host/Port**: 目标主机和端口
- **HTTPS**: 是否使用HTTPS
- **Encoding**: 选择编码方式
- **Content-Type**: Content-Type模板（自动更新charset）
- **Update Content-Type/Length**: 是否自动更新请求头

### 按钮功能
- **Encode Request**: 使用选中的编码编码请求
- **Fuzz All**: 生成所有编码的请求
- **Send Selected**: 发送选中的Fuzz请求
- **Send All Fuzz**: 发送所有Fuzz请求
- **Clear**: 清空所有内容

### Fuzz结果
- 单击行查看详细请求和响应
- 双击行发送该请求

## WAF绕过原理

```
          正常请求                    编码后请求
    ┌─────────────────┐         ┌─────────────────┐
    │ POST /api       │         │ POST /api       │
    │ Content-Type:   │   ──►   │ Content-Type:   │
    │   text/xml      │         │   text/xml;     │
    │                 │         │   charset=ibm037│
    │ <payload>       │         │ [EBCDIC bytes]  │
    └─────────────────┘         └─────────────────┘
            │                           │
            ▼                           ▼
    ┌─────────────────┐         ┌─────────────────┐
    │      WAF        │         │      WAF        │
    │  ✗ Blocked      │         │  ✓ Passed       │
    └─────────────────┘         └─────────────────┘
```

1. **EBCDIC编码**: IBM大型机使用的古老编码，绝大多数WAF不支持解析
2. **UTF-16/32编码**: 多字节宽字符编码，WAF可能无法正确解析
3. **ISO/Windows编码**: 特殊字符集，可能绕过字符检测

## 结果分析

| 状态码 | 含义 |
|-------|------|
| 500 | 请求到达后端，可能绕过了WAF |
| 400 | 服务器无法解析该编码 |
| 200 | 请求成功，编码被服务器正确解析 |
| 无响应 | 可能触发了WAF拦截 |

## 截图

```
┌──────────────────────────────────────────────────────────────┐
│  WAF Bypass Encoder                                          │
├──────────────────────────────────────────────────────────────┤
│  Host: [target.com  ] Port: [80  ] ☑HTTPS  Encoding: [IBM037]│
│  Content-Type: [text/xml; charset={encoding}     ]           │
│  [Encode] [Fuzz All] [Send Selected] [Send All] [Clear]      │
├──────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐  ┌─────────────────────┐            │
│  │ Full HTTP Request   │  │ Request Body        │            │
│  │                     │  │                     │            │
│  │ POST /api HTTP/1.1  │  │ <?xml version...    │            │
│  │ Host: target.com    │  │ <payload>           │            │
│  │ ...                 │  │ ...                 │            │
│  └─────────────────────┘  └─────────────────────┘            │
├──────────────────────────────────────────────────────────────┤
│  Fuzz Results                                                │
│  ┌─────┬──────────┬─────────────────┬────────┬───────┬─────┐│
│  │ #   │ Encoding │ Content-Type    │ Status │ Length│ Note││
│  ├─────┼──────────┼─────────────────┼────────┼───────┼─────┤│
│  │ 1   │ IBM037   │ text/xml;ibm037 │  500   │ 5092  │ Done││
│  │ 2   │ IBM500   │ text/xml;ibm500 │  400   │ 1024  │ Done││
│  │ 3   │ UTF-16   │ text/xml;utf-16 │  400   │ 512   │ Done││
│  └─────┴──────────┴─────────────────┴────────┴───────┴─────┘│
└──────────────────────────────────────────────────────────────┘
```

## 注意事项

1. 需要 Jython 2.7+ 环境
2. 某些编码在特定服务器上可能不被支持
3. 仅供授权安全测试使用

## 版本历史

- **v1.0** - 初始版本
  - 支持12种编码
  - Fuzz All功能
  - 批量发送请求

## License

MIT License

## 作者

Security Researcher
