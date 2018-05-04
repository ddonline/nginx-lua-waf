# Nginx-Lua-WAF概述
Nginx-Lua-WAF是一款基于Nginx的使用Lua语言开发的灵活高效的Web应用层防火墙。Lua语言的灵活和不亚于C语言的执行效率，保证了在做为网站应用层防火墙时，功能和性能之间完美的平衡，整个防火墙系统对性能的消耗几乎可以忽略不计。

Nginx-Lua-WAF完全可以放心在生产环境中使用，整个防火墙仅由5个lua程序文件组成，逻辑清晰，代码简单易懂，并配有较为详细的注释。整个代码全部读完也不会超过半个小时。强列建议先看下代码，相信你能很容易看懂。

本项目推荐使用由春哥(章亦春)维护的基于Nginx和LuaJIT的Web平台OpenResty作为Web服务器。OpenResty可以看作是在Nginx中添加了Lua的支持，并集成了常用的各类Lua库。当然，也可以手动编译Nginx，在编译中添加lua-nginx-module。

# 主要特性
防火墙只是一个框架，核心是rule规则文件，源码中规则文件仅供参考，在实际的使用过程中，接合自己的业务特点，可以灵活开关各项功能，以及增添各种规则。
- 支持对特定站点特定IP和特定URL组合的访问频率控制，即可以通过配置的百分比控制返回真实数据或预先配置的JSON字符串，该功能通常用于希望控制访问频率的接口，不希望客户端高频访问，以优雅的方式减少服务端不必要的性能开销
- Nginx工作于web服务器模式，可以有多个不同的站点，仅需要配置hostname就可以对不同的站点应用不同的规则，或者使用全局的规则
- 规则使用正则匹配，灵活性高
- 支持IP白名单、IP黑名单、UserAgent、URL白名单、URL、Cookie、请求参数、POST级别的过滤，每个功能均有独立开关，可以自由启用需要的过滤功能，并且在规则层面都是可以基于站点的
- 支持对CC攻击的防护
- 完整的日志记录功能，JSON格式日志，方便后期通过ELK集中管理
- 匹配规则后，支持回显html字符串、跳转到指定URL和不处理三种模式，其不设置为不处理后，仅记录日志，并不真正执行拦截动作，方便在生产环境中调试，不影响业务
- 安装、部署和维护非常简单
- 重载规则不会中断正常业务
- 跨平台，Nginx可以运行在哪里，WAF就可以运行在哪里

# 性能测试
Nginx-Lua-WAF拥有非常高的性能，在虚拟机中测试结果如下：
- 系统：CentOS Linux release 7.3.1611 (Core)
- 内核：3.10.0-514.el7.x86_64
- 内存：1G
- CPU：1核心 Intel(R) Core(TM) i7-4600U CPU @ 2.10GHz
- 测试命令：ab -n 10000 -c 50 http://127.0.0.1/index.html

### 关闭waf时测试
每秒处理14806次请求,处理单个请求平均3毫秒

![20180503174007.png](https://raw.githubusercontent.com/ddonline/nginx-lua-waf/master/other/20180503174007.png)
### 开启waf时测试
(开启所有功能，因为有cc检测，将cc阈值设置为20000/60防止压测时被拦截)
每秒处理9581次请求,处理单个请求平均5毫秒

![20180503174354.png](https://raw.githubusercontent.com/ddonline/nginx-lua-waf/master/other/20180503174354.png)
##### 可以看出启用waf后，Nginx性能依然非常高，近10k次的处理能力，能够满足任何业务场景的需要

# Nginx-Lua-WAF处理流程
![WAF.png](https://raw.githubusercontent.com/ddonline/nginx-lua-waf/master/other/WAF.png)

# 安装部署
## 以CentOS 7为例
### 编译安装openresty

从[openresty](http://openresty.org/cn/download.html)官方下载最新版本的源码包。

01、编译安装openresty：

```bash
#安装工具
yum -y install wget
#准备编译环境
yum -y install gcc
#准备依赖包
yum -y install install perl openssl openssl-devel
#下载并解压源码包
wget https://openresty.org/download/openresty-1.13.6.1.tar.gz
tar zxf openresty-1.13.6.1.tar.gz
#编译安装
cd openresty-1.13.6.1
./configure
make
make install
#默认openresty会安装到/usr/local/openresty目录
#nginx配置文件位置:/usr/local/openresty/nginx/conf/nginx.conf
#nginx站点目录:/usr/local/openresty/nginx/html
#nginx可执行文件位置:/usr/local/openresty/nginx/sbin/nginx
#后续工作
#临时关闭selinux
setenforce 0
#开启防火墙
#开启80端口的两种方式
firewall-cmd --permanent --zone=public --add-port=80/tcp
firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --reload  #重载防火墙，使配置生效
#启动nginx
/usr/local/openresty/nginx/sbin/nginx -t  #检查配置文件语法是否正确
/usr/local/openresty/nginx/sbin/nginx     #启动nginx
```

02、编译模块usertime.so

```bash
#usertime.c文件位于nginx-lua-waf/other/usertime.c
#编译好的usertime.so位于nginx-lua-waf/other/usertime.so
#如果平台和我的不一样建议自己编译usertime.so模块
#安装依赖包
yum -y install lua-devel
#编译模块usertime.so
cc -g -O2 -Wall -fPIC --shared usertime.c -o usertime.so
#将模块复制到lualib目录
cp usertime.so /usr/local/openresty/lualib
#如果是直接使用我编译的usertime.so，复制到lualib后需要授予可执行权限
chmod a+x /usr/local/openresty/lualib/usertime.so
```

03、部署Nginx-Lua-WAF

```
#安装工具
yum -y install unzip
#下载Nginx-Lua-WAF
wget https://github.com/ddonline/nginx-lua-waf/archive/master.zip
#解压缩
unzip master.zip  #解压后得到文件夹nginx-lua-waf-master
#对文件夹重命名
mv nginx-lua-waf-master nginx-lua-waf
#将nginx-lua-waf文件夹复制到nginx/conf目录下
cp -r nginx-lua-waf /usr/local/openresty/nginx/conf

#在nginx.conf中添加配置
vi /usr/local/openresty/nginx/conf/nginx.conf
在http级别添加以下内容:
    #nginx-lua-waf配置
    lua_package_path "/usr/local/openresty/nginx/conf/nginx-lua-waf/?.lua;";
    lua_shared_dict limit 100m;
    #开启lua代码缓存功能
    lua_code_cache on;
    lua_regex_cache_max_entries 4096;
    init_by_lua_file   /usr/local/openresty/nginx/conf/nginx-lua-waf/init.lua;
    access_by_lua_file /usr/local/openresty/nginx/conf/nginx-lua-waf/access.lua;
在server级别修改server_name:
    #在每个vhost中(server级别)定义server_name时，建议设置一个以上的主机名，默认第一个将做为规则中的主机区别标志，例如
    server_name  api api.test.com;
    
#修改config.lua中日志文件和规则文件路径和其它需要配置的项目
vi /usr/local/openresty/nginx/conf/nginx-lua-waf/config.lua
    config_log_dir = "/var/log/nginx",
    config_rule_dir = "/usr/local/openresty/nginx/conf/nginx-lua-waf/rules",
#修改日志目录权限,使nginx对目录可写
mkdir -p /var/log/nginx/
chmod o+w /var/log/nginx/
#重载nginx使配置生效
/usr/local/openresty/nginx/sbin/nginx -t  #检查配置文件语法是否正确
/usr/local/openresty/nginx/sbin/nginx -s reload    #重载nginx
#测试waf是否工作正常
curl http://127.0.0.1/test.zip
#若返回 "规则过滤测试" 字样，则说明waf已生效，url.rule中定义有规则阻止下载zip文件，此时/var/log/nginx/目录中应有类似2018-05-04_waf.log的JSON格式日志文件
#若返回 404 说明waf未生效
```

# 使用中注意事项
- waf配置文件：nginx-lua-waf/config.lua，各项配置均有注释说明
- 使用前请检查过滤规则是否符合自己实际情况，根据实际增删条目，防止误伤
- 规则文件除frequency.rule外全部为正则表达式，除frequency.rule、whiteip.rule、blackip.rule、whiteurl.rule外全部不区分大小写
- 规则文件中以"--"开头的为注释内容，除最后一行外，不能留有空行，且结尾字符应为LF
- 在用于生产环境时，可先将模式设置为jinghuashuiyue并检查拦截日志，确认有无误伤，该模式仅记录日志，不实际进行拦截(对IP黑名单和CC攻击过滤不适用，详见处理流程图)
- 更新规则文件后，使用reload命令(/usr/local/openresty/nginx/sbin/nginx -s reload)使用配置生效，该命令不会中断服务，不建议使用restart
- 部署过程中对openresty的安装使用的是默认选项，如果需要自定义，可以参考我的博文:[编译Nginx(OpenResty)支持Lua扩展](http://pdf.us/2018/03/19/742.html)


# 致谢

1. 感谢春哥开源的[openresty](https://openresty.org)
2. 开源项目：https://github.com/xsec-lab/x-waf
3. 开源项目：https://github.com/tluolovembtan/jsh_waf
4. 开源项目：https://github.com/loveshell/ngx_lua_waf
