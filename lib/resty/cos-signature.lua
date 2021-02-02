--[[
Copyright 2021 Mashiro (https://github.com/mashirozx)
Tencent QCloud COS Openresty request signature authorization headers generator

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
--]]

local resty_hmac = require('resty.hmac')
local resty_sha1 = require('resty.sha1')
local str = require('resty.string')

local _M = { _VERSION = '1.0.0' }

local function get_credentials()
  local access_key = os.getenv('COS_ACCESS_KEY_ID')
  local secret_key = os.getenv('COS_SECRET_ACCESS_KEY')

  return {
    access_key = access_key,
    secret_key = secret_key
  }
end

local function urlEncode(s)
  s = string.gsub(s, "([^%w%.%- ])", function(c) return string.format("%%%02X", string.byte(c)) end)
 return string.gsub(s, " ", "+")
end

local function urlDecode(s)
 s = string.gsub(s, '%%(%x%x)', function(h) return string.char(tonumber(h, 16)) end)
 return s
end

local function get_sha1(string)
  local sha1 = resty_sha1:new()
  if not sha1 then
      ngx.say("failed to create the sha1 object")
      return
  end

  local ok = sha1:update(string)
  if not ok then
      ngx.say("failed to add data")
      return
  end

  local digest = sha1:final()  -- binary digest

  return str.to_hex(digest)
end

local function get_hmac_sha1(key, message)
  local hmac_sha1 = resty_hmac:new(key, resty_hmac.ALGOS.SHA1)
  if not hmac_sha1 then
    ngx.say("failed to create the hmac_sha1 object")
    return
  end

  local ok = hmac_sha1:update(message)
  if not ok then
    ngx.say("failed to add data")
    return
  end

  local mac = hmac_sha1:final()  -- binary mac

  if not hmac_sha1:reset() then
    ngx.say("failed to reset hmac_sha1")
    return
  end

  return str.to_hex(mac)
end

local function get_request_uri()
  return ngx.var.uri
  -- return string.gsub(uri, replace, "" , 1)
end

-- 步骤1：生成 KeyTime
local function get_key_time(available_period)
  --local StartTimestamp = os.time()
  local StartTimestamp = ngx.time()
  local EndTimestamp = StartTimestamp + available_period
  local KeyTime = tostring(StartTimestamp) .. ';' .. EndTimestamp
  return {
    StartTimestamp = StartTimestamp,
    EndTimestamp = EndTimestamp,
    KeyTime = KeyTime
  }
end

-- 步骤2：生成 SignKey
-- 使用 HMAC-SHA1 以 SecretKey 为密钥，以 KeyTime 为消息，计算消息摘要（哈希值，16进制小写形式），即为 SignKey，例如：eb2519b498b02ac213cb1f3d1a3d27a3b3c9bc5f。
local function get_sign_key(SecretKey, KeyTime)
  return get_hmac_sha1(SecretKey, KeyTime)
end

-- 步骤3：生成 UrlParamList 和 HttpParameters
-- UrlParamList：delimiter;max-keys;prefix
-- HttpParameters：delimiter=%2F&max-keys=10&prefix=example-folder%2F
local function get_param_list()
  -- local arg = ngx.req.get_uri_args()
  local arg = {}
  -- local arg = {
  --  ['prefix'] = 'example-folder%2F',
  --  ['max-keys'] = '%2F'
  -- }
  local UrlParamList = ''
  local HttpParameters =''

  local arg_key_list = {}

  for k in pairs(arg) do table.insert(arg_key_list, k) end
  table.sort(arg_key_list, function(a, b) return a:upper() < b:upper() end)

  UrlParamList = table.concat(arg_key_list, ";")

  for kid,kvalue in pairs(arg_key_list) do
    local and_c = ''
    if (kid ~= 1)
    then
      and_c = '&'
    end
    HttpParameters = HttpParameters .. and_c .. kvalue .. "=" .. urlEncode(urlDecode(arg[kvalue]))
  end

  return {
    UrlParamList = UrlParamList,
    HttpParameters = HttpParameters
  }
  -- return UrlParamList .. '\n' .. HttpParameters
end

-- 步骤4：生成 HeaderList 和 HttpHeaders
-- HeaderList = date;host;x-cos-acl;x-cos-grant-read
-- HttpHeaders = date=Thu%2C%2016%20May%202019%2003%3A15%3A06%20GMT&host=examplebucket-1250000000.cos.ap-shanghai.myqcloud.com&x-cos-acl=private&x-cos-grant-read=uin%3D%22100000000011%22
local function get_header_list()
  -- local arg = ngx.req.get_headers()
  local arg = {}
  -- local arg = {
  --  ['prefix'] = 'example-folder%2F',
  --  ['max-keys'] = '%2F'
  -- }
  local HeaderList = ''
  local HttpHeaders =''

  local arg_key_list = {}

  for k in pairs(arg) do table.insert(arg_key_list, k) end
  table.sort(arg_key_list, function(a, b) return a:upper() < b:upper() end)

  HeaderList = table.concat(arg_key_list, ";")

  for kid,kvalue in pairs(arg_key_list) do
    local and_c = ''
    if (kid ~= 1)
    then
      and_c = '&'
    end
    HttpHeaders = HttpHeaders .. and_c .. kvalue .. "=" .. urlEncode(urlDecode(arg[kvalue]))
  end

  return {
    HeaderList = HeaderList,
    HttpHeaders = HttpHeaders
  }
  -- return HeaderList .. '\n' .. HttpHeaders
end

-- 步骤5：生成 HttpString
-- HttpMethod\nUriPathname\nHttpParameters\nHttpHeaders\n
local function get_http_string(HttpMethod, HttpParameters, HttpHeaders)
  local UriPathname = get_request_uri()
  -- local UriPathname = '/'
  local line_break = '\n'
  return HttpMethod:lower() .. line_break .. UriPathname .. line_break .. HttpParameters .. line_break .. HttpHeaders .. line_break
  -- HttpMethod\nUriPathname\nHttpParameters\nHttpHeaders\n
end

-- 步骤6：生成 StringToSign
-- sha1\nKeyTime\nSHA1(HttpString)\n
local function get_string_to_sign(KeyTime, HttpString)
  local line_break = '\n'
  local SHA1 = get_sha1(HttpString)
  return 'sha1' .. line_break .. KeyTime .. line_break .. SHA1 .. line_break
end

-- 步骤7：生成 Signature
-- 使用 HMAC-SHA1 以 SignKey 为密钥（字符串形式，非原始二进制），以 StringToSign 为消息，计算消息摘要，即为 Signature，例如：01681b8c9d798a678e43b685a9f1bba0f6c0e012
local function get_signature(SignKey, message)
  return get_hmac_sha1(SignKey, message)
end

-- 步骤8：生成签名
-- 根据 SecretId、KeyTime、HeaderList、UrlParamList 和 Signature 生成签名
local function get_auth_string(Sha, SecretId, KeyTime, HeaderList, UrlParamList, Signature)
  return 'q-sign-algorithm=' .. Sha
    .. '&q-ak=' .. SecretId
    .. '&q-sign-time=' .. KeyTime
    .. '&q-key-time=' .. KeyTime
    .. '&q-header-list=' .. HeaderList
    .. '&q-url-param-list=' .. UrlParamList
    .. '&q-signature=' .. Signature
end

function _M.cos_set_headers()
  local host = 'cos.ap-hongkong.myqcloud.com'
  local available_period = 60
  local Sha = 'sha1'
  local SecretId = get_credentials()['access_key']
  local SecretKey = get_credentials()['secret_key']

  -- 步骤1：生成 KeyTime
  local KeyTime = get_key_time(available_period)['KeyTime']
  -- 步骤2：生成 SignKey
  local SignKey = get_sign_key(SecretKey, KeyTime)
  -- 步骤3：生成 UrlParamList 和 HttpParameters
  local UrlParamList = get_param_list()['UrlParamList']
  local HttpParameters = get_param_list()['HttpParameters']
  -- 步骤4：生成 HeaderList 和 HttpHeaders
  local HeaderList = get_header_list()['HeaderList']
  local HttpHeaders = get_header_list()['HttpHeaders']
  -- 步骤5：生成 HttpString
  local HttpString = get_http_string('GET', HttpParameters, HttpHeaders)
  -- 步骤6：生成 StringToSign
  local StringToSign = get_string_to_sign(KeyTime, HttpString)
  -- 步骤7：生成 Signature
  local Signature = get_signature(SignKey, StringToSign)
  -- 步骤8：生成签名
  local AuthString = get_auth_string(
    Sha, SecretId, KeyTime, HeaderList, UrlParamList, Signature
  )

  ngx.req.set_header('Authorization', AuthString)
  -- ngx.log(ngx.ERR,
  --   '\n\n[Lua log]',
  --   '\n[Sha]', Sha,
  --   '\n[SecretId]', SecretId,
  --   '\n[KeyTime]', KeyTime,
  --   '\n[HeaderList]', HeaderList,
  --   '\n[UrlParamList]', UrlParamList,
  --   '\n[Signature]', Signature,
  --   '\n[AuthString]', AuthString,
  --   '\n=======',
  --   '\n[URI}', get_request_uri(),
  --   '\n[SignKey]', SignKey,
  --   '\n[HttpString]', HttpString,
  --   '\n[StringToSign]', StringToSign,
  --   '\n[Signature]', Signature)
end

return _M
