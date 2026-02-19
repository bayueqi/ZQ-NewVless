# ZQ-NewVless

![页面](src/3.png)
![页面](src/4.png)

## ✨ 功能特点

- 🚀 **多出站支持**：直连、SOCKS5代理、ProxyIP自动切换
- 🎛️ **Web配置管理**：通过Web界面管理所有配置，无需修改代码
- 🔒 **安全验证**：UUID验证确保只有授权用户能访问
- 📱 **响应式设计**：支持桌面和移动端访问
- 🎨 **优选工具集成**：内置优选域名,ProxyIP与订阅链接转换工具链接
- ⚡ **高性能**：基于Cloudflare Workers，全球加速

## 🚀 部署步骤

### 1. 部署到Workers

1. 登录 Cloudflare 控制台
2. 左侧进入 **Workers 和 Pages**
3. 点击 **创建应用程序** → 选择 **创建 Worker**
4. 输入 Worker 名称并创建
5. 进入在线编辑器：
   - 删除默认模板代码
   - 打开本仓库的 `_worker.js`，复制全部内容
   - 粘贴到 Cloudflare 在线编辑器中
6. 点击右上角 **保存并部署**
7. 创建 KV 命名空间：
   - 左侧进入 **存储和数据库**，点击**KV**
   - 点击 **创建命名空间**，名称建议：`NewVless`
8. 在 Worker 详情页绑定 KV：
   - 打开 Worker → **设置** → **变量** → **KV 命名空间绑定** → **添加绑定**
   - 变量名称：`NewVless`
   - 选择刚创建的 KV 命名空间
   - 点击 **保存**
9. 绑定自定义域名(`注意:不能使用workers默认域名`)

### 2. 部署到Pages
1. [下载 ZIP包](https://codeload.github.com/BAYUEQI/ZQ-NewVless/zip/refs/heads/main)
2. 登录 Cloudflare → **Workers 和 Pages** → **创建应用程序** → 选择 **创建 Pages**
3. 选择 **直接上传**，上传下载的 ZIP 包,直接保存并部署 
4. 创建 KV 命名空间：
   - 左侧进入 **存储和数据库**，点击**KV**
   - 点击 **创建命名空间**，名称建议：`NewVless`
5. 绑定 KV：进入 Pages 项目 → **设置** → **变量** → **KV 命名空间绑定** → **添加绑定**
   - 变量名称：`NewVless`
   - 选择已创建的 KV 命名空间
6. 再次上传 ZIP 包并部署，接着访问域名(`可以绑定自定义域名，也可使用pages默认域名`)


## 📖 使用说明

### 首次使用

1. 访问你的项目域名
2. 输入`ef9d104e-ca0e-4202-ba4b-a0afb969c747`进入节点界面
3. 点击右上角 **⚙️** 按钮进入配置管理
4. 配置你的代理设置：
   - **UUID**：强烈建议修改，用于身份验证
   - **优选ip**：可选，默认worker域名
   - **端口**：可选，默认443(可填443系端口:443、2053、2083、2087、2096、8443)
   - **SOCKS5代理**：可选，格式 `user:pass@host:port`或者`host:port`
   - **ProxyIP**：可选，格式 `host:port`或者`host`
   - **回退检测时间**：可选，100-10000毫秒，默认1000(如果某个节点不通但是socks5或proxyip有效，可调节此值)
5. 点击主页面右上角 **🔗** 按钮可以访问订阅链接转换工具，帮助适配不同客户端。



## 🛠️ 手搓节点
路径参数

* `/?mode=direct`（仅直连）
* `/?mode=s5&s5=user:pass@host:port`（仅SOCKS5）
* `/?mode=auto&direct&s5=user:pass@host:port`（直连优先，回退SOCKS5）
* `/?mode=auto&s5=user:pass@host:port&direct`（SOCKS5优先，回退直连）
* `/?mode=auto&direct&proxyip=host:port`（直连优先，回退ProxyIP）
* `/?mode=auto&proxyip=host:port&direct`（ProxyIP优先，回退直连）
* `/?mode=auto&s5=user:pass@host:port&proxyip=host:port`（SOCKS5优先，回退ProxyIP）
* `/?mode=auto&proxyip=host:port&s5=user:pass@host:port`（ProxyIP优先，回退SOCKS5）
* `/?mode=auto&direct&s5=user:pass@host:port&proxyip=host:port`（三者：直连→SOCKS5→ProxyIP）
* `/?mode=auto&direct&proxyip=host:port&s5=user:pass@host:port`（三者：直连→ProxyIP→SOCKS5）
* `/?mode=auto&s5=user:pass@host:port&direct&proxyip=host:port`（三者：SOCKS5→直连→ProxyIP）
* `/?mode=auto&s5=user:pass@host:port&proxyip=host:port&direct`（三者：SOCKS5→ProxyIP→直连）
* `/?mode=auto&proxyip=host:port&direct&s5=user:pass@host:port`（三者：ProxyIP→直连→SOCKS5）
* `/?mode=auto&proxyip=host:port&s5=user:pass@host:port&direct`（三者：ProxyIP→SOCKS5→直连）

> 注意：不支持“仅 ProxyIP”模式
![手搓](src/1.png)
![手搓](src/2.png)



## 🤝 贡献

欢迎提交Issue和Pull Request！



## 🔗 相关链接

[workers-vless](https://github.com/ymyuuu/workers-vless)
## ☕️ 请我喝杯奶茶

如果本项目对你有帮助，欢迎请我喝杯奶茶 

<p align="center">
  <img src="https://blog.520jacky.ip-ddns.com/img/8.jpg" alt="请我喝杯奶茶" width="220" />
</p>



