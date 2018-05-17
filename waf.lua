-- 高精度时间
local utime = require "usertime"

local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

local config = require("config")
local util = require("util")

local _M = {
    RULES = {}
}

-- 载入规则到本模块RULES字典
function _M.load_rules()
    _M.RULES = util.get_rules(config.config_rule_dir)
    for k, v in pairs(_M.RULES)
    do
        ngx.log(ngx.INFO, string.format("%s规则载入中...", k))
        for kk, vv in pairs(v)
        do
            ngx.log(ngx.INFO, string.format("编号:%s, 规则:%s", kk, vv))
        end
    end
    return _M.RULES
end

-- 获取RULES字典中指定类型规则列表
function _M.get_rule(rule_file_name)
    return _M.RULES[rule_file_name]
end

-- 白名单IP检查
-- 匹配字段式样:api-192.168.1.1
function _M.white_ip_check()
    if config.config_white_ip_check == "on" then
        local IP_WHITE_RULE = _M.get_rule('whiteip.rule')
        local WHITE_IP = ngx.var.server_name.."-"..util.get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _, rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and rulematch(WHITE_IP, rule, "jo") then
                    -- 为优化性能 白名单不记录日志
                    -- util.log_record(config.config_log_dir, '白名单IP', ngx.var_request_uri, "_", "_")
                    return true
                end
            end
        end
    end
end

-- 黑名单IP检查
-- 匹配字段式样:api-192.168.1.1
function _M.black_ip_check()
    if config.config_black_ip_check == "on" then
        local IP_BLACK_RULE = _M.get_rule('blackip.rule')
        local BLACK_IP = ngx.var.server_name.."-"..util.get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _, rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP, rule, "jo") then
                    util.log_record(config.config_log_dir, '黑名单IP', ngx.var_request_uri, "_", rule)
                    ngx.exit(403)
                    return true
                end
            end
        end
    end
end

-- UserAgent检查
-- 匹配字段式样:api-Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0
function _M.user_agent_attack_check()
    if config.config_user_agent_check == "on" then
        local USER_AGENT = ngx.var.http_user_agent
        local USER_AGENT_RULES = _M.get_rule('useragent.rule')
        if USER_AGENT ~= nil then
            for _, rule in pairs(USER_AGENT_RULES) do
                if rule ~= "" and rulematch((ngx.var.server_name.."-"..USER_AGENT), rule, "joi") then
                    util.log_record(config.config_log_dir, 'UserAgent受限', ngx.var.request_uri, "-", rule)
                    util.waf_output()
                    return true
                end
            end
        end
    end
    return false
end

-- 白名单URL
-- 匹配字段式样:api-index.html
function _M.white_url_check()
    if config.config_white_url_check == "on" then
        local URL_WHITE_RULES = _M.get_rule('whiteurl.rule')
        local REQ_URI = ngx.var.server_name.."-"..ngx.var.uri
        if URL_WHITE_RULES ~= nil then
            for _, rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI, rule, "joi") then
                    return true
                end
            end
        end
    end
end

-- URL检查
-- 匹配字段式样:api-index.html
function _M.url_attack_check()
    if config.config_url_check == "on" then
        local URL_RULES = _M.get_rule('url.rule')
        local REQ_URI = ngx.var.server_name.."-"..ngx.var.uri
        for _, rule in pairs(URL_RULES) do
            if rule ~= "" and rulematch(REQ_URI, rule, "joi") then
                util.log_record(config.config_log_dir, '非法URL', ngx.var.request_uri, "-", rule)
                util.waf_output()
                return true
            end
        end
    end
    return false
end

-- CC攻击
-- 匹配字段式样:api-192.168.158.1-/index.html
-- 使用共享存储limit
function _M.cc_attack_check()
    if config.config_cc_check == "on" then
        local ATTACK_URI = ngx.var.uri
        local CC_TOKEN = ngx.var.server_name.."-"..util.get_client_ip() .."-"..ATTACK_URI
        local limit = ngx.shared.limit
        local CCcount = tonumber(string.match(config.config_cc_rate, '(.*)/'))
        local CCseconds = tonumber(string.match(config.config_cc_rate, '/(.*)'))
        local req, _ = limit:get(CC_TOKEN)
        -- 打印目标限制字符串
        -- ngx.log(ngx.ERR, "错误:" .. CC_TOKEN)
        if req then
            if req > CCcount then
                util.log_record(config.config_log_dir, 'CC攻击', ngx.var.request_uri, "-", "-")
                ngx.exit(403)
            else
                limit:incr(CC_TOKEN, 1)
            end
        else
            limit:set(CC_TOKEN, 1, CCseconds)
        end
    end
    return false
end

-- Cookie检查
-- 匹配字段式样:api-nc_sameSiteCookielax=true; nc_sameSiteCookiestrict=true; 
-- kod_user_language=zh_CN; kod_user_online_version=check-at-1523267590; kod_name=admin; 
-- kod_token=3e016b80ce1e7349ff371324a1c0f996, client: 192.168.158.1, server: api, 
-- request: "GET /index.html HTTP/1.1", host: "192.168.158.139"
function _M.cookie_attack_check()
    if config.config_cookie_check == "on" then
        local COOKIE_RULES = _M.get_rule('cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            USER_COOKIE = ngx.var.server_name.."-"..USER_COOKIE
            for _, rule in pairs(COOKIE_RULES) do
                if rule ~= "" and rulematch(USER_COOKIE, rule, "joi") then
                    util.log_record(config.config_log_dir, '非法Cookie', ngx.var.request_uri, "-", rule)
                    util.waf_output()
                    return true
                end
            end
        end
    end
    return false
end

-- 请求参数检查
-- 匹配字段式样:api-3
-- ?a   不检查,REQ_ARGS => table;ARGS_DATA => boolean
-- ?a=3 检查的是3
function _M.url_args_attack_check()
    if config.config_url_args_check == "on" then
        local ARGS_RULES = _M.get_rule('args.rule')
        for _, rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            for key, val in pairs(REQ_ARGS) do
                local ARGS_DATA = {}
                if type(val) == 'table' then
                    ARGS_DATA = table.concat(val, " ")
                else 
                    ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~= "" and rulematch(unescape(ngx.var.server_name.."-"..ARGS_DATA), rule, "joi") then
                    util.log_record(config.config_log_dir, '参数非法', ngx.var.request_uri, "-", rule)
                    util.waf_output()
                    return true
                end
            end
        end
    end
    return false
end

-- POST检查
-- 匹配字段式样:api-txt
-- multipart/form-data方式的数据，只要其中带有文件，则不检查
-- application/x-www-form-urlencoded二进制模式发送的文件会被检查
-- 日志中的post_data并非完整的POST数据
function _M.post_attack_check()
    if config.config_post_check == "on" and ngx.req.get_method() ~= "GET" then
        ngx.req.read_body()
        local POST_RULES = _M.get_rule('post.rule')
        local POST_ARGS = ngx.req.get_post_args() or {}
        -- 输出POST_ARGS内容
        -- for kk,vv in  pairs(POST_ARGS) do
        --     ngx.log(ngx.ERR, "错误:"..kk)
        --     ngx.log(ngx.ERR, "错误:"..vv)
        -- end
        for _, rule in pairs(POST_RULES) do
            for k, v in pairs(POST_ARGS) do
                local post_data = ""
                if type(v) == "table" then
                    -- 重构table,解决“nvalid value (boolean) at index 1 in table for 'concat'”
                    local tt={}
                    for kk,vv in pairs(v) do
                        if type(vv) ~= "boolean" then
                            vv="-"
                        end
                        table.insert(tt,vv)
                    end
                    post_data = ngx.var.server_name.."-"..table.concat(tt, ",")
                elseif type(v) == "boolean" then
                    post_data = ngx.var.server_name.."-"..k
                else
                    post_data = ngx.var.server_name.."-"..v
                end
                -- 选项s强制多行为一行对待，否则非第一行将不匹配
                if rule ~= "" and rulematch(post_data, rule, "jois") then
                    util.log_record(config.config_log_dir, 'POST非法数据', ngx.var.request_uri, post_data, rule)
                    util.waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--[[
-- 镜花水月模式
-- 检查来访IP是否为标记过的恶意IP
function _M.bad_guy_check()
    local client_ip = util.get_client_ip()
    local ret = false
    if client_ip ~= "" then
        ret = ngx.shared.badGuys.get(client_ip)
        if ret ~= nil and ret > 0 then
            ret = true
        end
    end
    return ret
end

-- 镜花水月模式
-- 获取来访请求头中目标Host字段，并设置为target变量
-- 如果该IP被标注为恶意IP 则改写target变量 使其路由到测试环境
function _M.start_jingshuishuiyue()
    local host = util.get_server_host()  -- 获取请求头中Host字段
    ngx.var.target = string.format("proxy_%s", host)
    if host and _M.bad_guy_check() then
        ngx.var.target = string.format("unreal_%s", host)
    end
end
]]

-- 加入频率控制函数
-- 若返回假数据，将跳过后续检查流程
function _M.frequency_control_check()
    if config.frequency_control_check == "on" then
        local FREQUENCY_RULE = _M.get_rule('frequency.rule')
        -- 目标 api-192.168.123.33-index.html
        local FREQUENCY_TAG = ngx.var.server_name.."-"..util.get_client_ip().."-"..ngx.var.uri
        if FREQUENCY_RULE ~= nil then
            for _, rule in pairs(FREQUENCY_RULE) do
                -- ngx.log(ngx.ERR, "错误1:FREQUENCY_TAG:" .. FREQUENCY_TAG) --api-192.168.158.1-/index.html
                -- ngx.log(ngx.ERR, "错误2:" .. rule)                        --api-192.168.158.1-/index.html-3
                -- ngx.log(ngx.ERR, "错误3:" .. string.sub(rule,-1,-1))      --3
                -- ngx.log(ngx.ERR, "错误4:" .. string.sub(rule,1,-3))       --api-192.168.158.1-/index.html
                if rule ~= "" and string.sub(rule,1,-3) == FREQUENCY_TAG then
                    local microsecond = utime.getmillisecond()
                    math.randomseed(tostring(microsecond):reverse():sub(1,12))
                    if math.random(0,9) >= tonumber(string.sub(rule,-1,-1)) then
                        util.log_record(config.config_log_dir, '假数据', ngx.var_request_uri, "_", "_")
                        ngx.header.content_type = "application/json" --text/html
                        ngx.header.content_length = #config.frequency_text
                        ngx.status = ngx.HTTP_OK
                        ngx.say(config.frequency_text)   -- 直接退出流程！
                        -- ngx.log(ngx.ERR, "错误:假数据") 
                        ngx.exit(ngx.status)
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- 执行检查
-- CC处理方式：limit计数，记录日志，返回403
-- IP黑名单处理方式：记录日志，返回403
-- 其它方式：记录日志，调用waf_output函数处理
function _M.check()
    if config.config_waf_enable ~= "on" then
        return
    end
    if     _M.frequency_control_check() then
    -- if     _M.white_ip_check() then
    elseif _M.white_ip_check() then
    elseif _M.black_ip_check() then
    elseif _M.user_agent_attack_check() then
    elseif _M.white_url_check() then
    elseif _M.url_attack_check() then
    elseif _M.cc_attack_check() then
    elseif _M.cookie_attack_check() then
    elseif _M.url_args_attack_check() then
    elseif _M.post_attack_check() then
    else
        return
    end
end

return _M