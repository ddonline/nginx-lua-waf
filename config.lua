--[[
说明：
1、nginx配置：在http级别添加以下内容
    #nginx-lua-waf配置
    lua_package_path "/usr/local/openresty/nginx/conf/nginx-lua-waf/?.lua;";
    lua_shared_dict limit 100m;
    #开启lua代码缓存功能
    lua_code_cache on;
    lua_regex_cache_max_entries 4096;
    init_by_lua_file   /usr/local/openresty/nginx/conf/nginx-lua-waf/init.lua;
    access_by_lua_file /usr/local/openresty/nginx/conf/nginx-lua-waf/access.lua;
2、vhost配置：server_name第一个名称为规则主机限制时的关键词
    server_name  api api.test.com;
3、规则格式：
    所有规则均可添加主机限制，如api-index.html  这会仅限制api站点的访问
    如果不添加，则为全局限制
4、规则文件一行一条规则
5、规则文件可以使用"--"进行注释
6、规则文件需要LF行结尾 否则会发生问题
7、性能：
   ab -n 10000 -c 50 http://127.0.0.1/index.html
   关闭waf  Requests per second:    14806 [#/sec] (mean)
   打开waf  Requests per second:    9581  [#/sec] (mean)
8、日志存放文件夹需要有写放权限 chmod o+w /var/log/nginx/
]]
-- enable = "on", disable = "off"

local _M = {
    -- 防火墙开关
    config_waf_enable = "on",
    -- 日志文件存放目录 结尾不带/
    config_log_dir = "/var/log/nginx",
    -- 规则文件存放目录 结尾不带/
    config_rule_dir = "/usr/local/openresty/nginx/conf/nginx-lua-waf/rules",

--01假数据时不进行后续流程，非正则匹配
    -- 频率控制开关
    frequency_control_check = "on",
    -- 频率控制中返回空数据内容
    frequency_text = [[{"status":"ok"}]],

--02直接通过不进行后续流程
    -- IP白名单开关
    config_white_ip_check = "on",

--03返回403
    -- IP黑名单开关
    config_black_ip_check = "on",

--04WAF处理:跳转/html/仅日志
    -- UserAgent过滤开关
    config_user_agent_check = "on",

--05直接通过不进行后续流程
    -- URL白名单开关
    config_white_url_check = "on",

--06WAF处理:跳转/html/仅日志
    -- URL过滤开关
    config_url_check = "on",

--07返回403记录limit
    -- CC攻击过滤开关
    config_cc_check = "on",
    -- 设置CC攻击检测依据 攻击阈值/检测时间段
    config_cc_rate = "3000/60",

--08WAF处理:跳转/html/仅日志
    -- Cookie过滤开关
    config_cookie_check = "on",

--09WAF处理:跳转/html/仅日志
    -- ARGS请求参数过滤开关
    config_url_args_check = "on",
    
--10WAF处理:跳转/html/仅日志
    -- POST过滤开关
    config_post_check = "on",
    -- 处理方式 redirect/html/jinghuashuiyue  jinghuashuiyue只记录日志
    config_waf_model = "html",
    -- 当配置为redirect时跳转到的URL
    config_waf_redirect_url = "http://www.baidu.com",
    -- bad_guys过期时间
    -- config_expire_time = 600,
    -- 当配置为html时 显示的内容
    config_output_html = [[
    <html>
    <head>
    <meta charset="UTF-8">
    <title>LEPEI WAF</title>
    </head>
      <body>
        <div>
      <div class="table">
        <div>
          <div class="cell">
            您的IP为: %s
          </div>
          <div class="cell">
            已触发WAF规则
          </div>
          <div class="cell">
            实际使用请修改此提示信息
          </div>
        </div>
      </div>
    </div>
      </body>
    </html>
    ]],
}

return _M