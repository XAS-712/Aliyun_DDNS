# Aliyun_DDNS
<h3>Run with Python2.7 OR 3.x（待重构）</h3>
<h4>贡献者：@AndroidOL</h4>
依赖 urllib 库，用于访问 API 以及获取地址<br />
可选使用 aliyunsdkcore 简化本地操作，请使用 pip 安装<br />
利用 Aliyun 解析 API 编写的 DDNS 脚本，支持主动添加解析<br />
请自行修改程序中的域名、API-Key 等变量，支持 Mailgun 邮件 API<br />
<h2>为啥要写这么个玩意</h2>
真相是这样的，我自己搞了台小服务器在家里跑着自动查图书馆的书是否超期等脚本，偶尔也要连上去看看，或者当个 bridge 使连 RDP 到台式机，网络环境是动态公网IP，一直用 oray 的 DDNS。可惜这家现在越做越坑，还限制子域名数量，后来发现阿里云是个好东西，于是就有了这个脚本。
<h2>这个玩意怎么玩</h2>
把配置信息写好，把它写进 crontab 里，五分钟一次。
