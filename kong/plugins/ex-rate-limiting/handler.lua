-- Beauli Zhu.

local policies = require "kong.plugins.rate-limiting.policies"
local timestamp = require "kong.tools.timestamp"
local responses = require "kong.tools.responses"
local BasePlugin = require "kong.plugins.base_plugin"
local iputils = require "resty.iputils"
local singletons = require "kong.singletons"
local json = require "lunajson"

local ngx_log = ngx.log
local pairs = pairs
local tostring = tostring
local ngx_timer_at = ngx.timer.at

local RATELIMIT_LIMIT = "X-ExRateLimit-Limit"
local RATELIMIT_REMAINING = "X-ExRateLimit-Remaining"

local get_headers = ngx.req.get_headers;

local ExRateLimitingHandler = BasePlugin:extend()

ExRateLimitingHandler.PRIORITY = 900

local function get_ip()
  -- local ip = headers["X-Real-IP"]
  -- if ip == nil then
  --   ip = headers["x_forwarded_for"]
  -- end
  -- if ip == nil then
  return ngx.var.remote_addr
  -- end
  -- return ip
end

local function check_ip_should_ignore(ip,conf)
  local ignore = false
  if conf.white_ip_list and #conf.white_ip_list > 0 then
    ignore = iputils.ip_in_cidrs(ip, iputils.parse_cidrs(conf.white_ip_list))
  end
  return ignore
end

local function get_identifier(conf,headers)
  local identifier
  local identifier_type = conf.limit_by
  -- Consumer is identified by ip address or authenticated_credential id
  if conf.limit_by == "consumer" then
    
    identifier = ngx.ctx.authenticated_consumer and ngx.ctx.authenticated_consumer.id
    if not identifier and ngx.ctx.authenticated_credential then -- Fallback on credential
      identifier = ngx.ctx.authenticated_credential.id
    end
  elseif conf.limit_by == "credential" then
    identifier = ngx.ctx.authenticated_credential and ngx.ctx.authenticated_credential.id
  elseif conf.limit_by == "header" then
    local limit_by_value = string.lower(conf.limit_by_value)
    if headers[limit_by_value] then
      identifier= limit_by_value..":"..string.lower(headers[limit_by_value])
    end
  end
  
  if not identifier then 
    identifier_type = "ip"
    local ip = get_ip()
    identifier = ip
  end

  return identifier_type,identifier
end

local function get_usage(conf, api_id, identifier, current_timestamp, limits)
  local usage = {}
  local stop

  for name, limit in pairs(limits) do
    local current_usage, err = policies[conf.policy].usage(conf, api_id, identifier, current_timestamp, name)
    if err then
      return nil, nil, err
    end

    -- What is the current usage for the configured limit name?
    local remaining = limit - current_usage

    -- Recording usage
    usage[name] = {
      limit = limit,
      remaining = remaining
    }

    if remaining <= 0 then
      stop = name
    end
  end

  return usage, stop
end

function ExRateLimitingHandler:new()
  ExRateLimitingHandler.super.new(self, "ex-rate-limiting")
end

function ExRateLimitingHandler:access(conf)
  ExRateLimitingHandler.super.access(self)
  

  local ip = get_ip()
  local ignore_limit = check_ip_should_ignore(ip,conf)

  if ignore_limit then return end

  local headers = get_headers()

  local current_timestamp = timestamp.get_utc()

  -- Consumer is identified by ip address or authenticated_credential id
  local identifier_type,identifier_value = get_identifier(conf,headers)
  local api_id = ngx.ctx.api.id
  local policy = conf.policy
  local fault_tolerant = conf.fault_tolerant
  local identifier = identifier_type ..":"..identifier_value

  local log_request = function(premature,log_body)
    if premature then return end
    singletons.dao.exratelimiting_metrics:record_request(
      log_body.api_id,
      log_body.identifier_type,
      log_body.identifier_value,
      log_body.ip,
      log_body.request_uri,
      log_body.timestamp)
  end

  local log_entity = {
    api_id=api_id,
    request_uri=ngx.var.request_uri,
    identifier_type=identifier_type,
    identifier_value=identifier_value,
    ip=ip,
    timestamp=current_timestamp,
  }

  local ok, err = ngx_timer_at(0, log_request, log_entity)
  if not ok then
    ngx_log(ngx.ERR, "failed to create timer: ", err)
  end

  -- Load current metric for configured period
  local usage, stop, err = get_usage(conf, api_id, identifier, current_timestamp, {
    second = conf.second,
    minute = conf.minute,
    hour = conf.hour,
    day = conf.day,
    month = conf.month,
    year = conf.year
  })
  if err then
    if fault_tolerant then
      ngx_log(ngx.ERR, "failed to get usage: ", tostring(err))
    else
      return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
    end
  end

  if usage then
    -- Adding headers
    if conf.show_limit_in_header then
      for k, v in pairs(usage) do
        ngx.header[RATELIMIT_LIMIT.."-"..k] = v.limit
        ngx.header[RATELIMIT_REMAINING.."-"..k] = math.max(0, (stop == nil or stop == k) and v.remaining - 1 or v.remaining) -- -increment_value for this current request
      end
    end

    -- If limit is exceeded, terminate the request
    if stop then
      return responses.send(429, "API rate limit exceeded")
    end
  end

  local incr = function(premature, conf, api_id, identifier, current_timestamp, value)
    if premature then return end
    policies[policy].increment(conf, api_id, identifier, current_timestamp, value)
  end

  -- Increment metrics for all periods if the request goes through
  local ok, err = ngx_timer_at(0, incr, conf, api_id, identifier, current_timestamp, 1)
  if not ok then
    ngx_log(ngx.ERR, "failed to create timer: ", err)
  end
end

return ExRateLimitingHandler