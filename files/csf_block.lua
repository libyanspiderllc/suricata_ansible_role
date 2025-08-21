#!/usr/bin/env lua
-- Suricata CSF Integration Script
-- This script reads Suricata alerts and blocks malicious IPs using CSF firewall

-- Configuration
local config = {
  log_file = "/var/log/suricata/csf_block.log",  -- Log file for this script
  block_duration = "3600",                        -- Block duration in seconds (1 hour)
  csf_path = "/usr/sbin/csf",                    -- Path to CSF executable
  min_priority = 1,                               -- Minimum alert priority to trigger blocking
  block_sids = {                                 -- List of Suricata rule IDs that trigger blocking
      1000001,    -- LS WORDPRESS XMLRPC.PHP Brute Force Attempt
      2031505     -- ET SCAN WordPress Scanner Performing Multiple Requests to Windows Live Writer XML
      
  }
}

-- Convert sids list to a lookup table for better performance
local block_sids_lookup = {}
for _, sid in ipairs(config.block_sids) do
  block_sids_lookup[sid] = true
end

-- Check if IP is valid
local function is_valid_ip(ip)
  if not ip then return false end
  
  local chunks = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
  if #chunks ~= 4 then return false end
  
  for _, v in pairs(chunks) do
      local num = tonumber(v)
      if not num or num < 0 or num > 255 then return false end
  end
  
  return true
end

-- Initialize logging
local function logit(message)
  local file = io.open(config.log_file, "a")
  if file then
      local timestamp = os.date("%Y-%m-%d %H:%M:%S")
      file:write(string.format("[%s] %s\n", timestamp, message))
      file:close()
  end
end

-- Block IP using CSF
local function block_ip(ip, description, port)
  if not is_valid_ip(ip) then
      log(string.format("Invalid IP address format: %s", ip))
      return false
  end
  
  -- Check if IP is already blocked using csf -g
  local check_cmd = string.format("%s -g %s", config.csf_path, ip)
  local check_handle = io.popen(check_cmd)
  local check_result = check_handle:read("*a")
  check_handle:close()
  
  if check_result:find("csf.deny") or check_result:find("Temporary Blocks") then
      logit(string.format("IP %s is already blocked", ip))
      return true
  end
  
  -- Block the IP using CSF with description
  local comment = string.format("Blocked by Suricata - %s", description or "Unknown rule")
  local block_cmd = string.format("%s -td %s %s -p %s \"%s\"", config.csf_path, ip, config.block_duration, port, comment)
  local success = os.execute(block_cmd)
  
  if success then
      logit(string.format("Successfully blocked IP %s on port %s for %s seconds (%s)", ip, port, config.block_duration, comment))
      return true
  else
      logit(string.format("Failed to block IP %s", ip))
      return false
  end
end

function init (args)
  local needs = {}
  needs["type"] = "packet"
  needs["filter"] = "alerts"
  return needs
end

function setup (args)
  -- The first log will be used to determine if the report
  -- was a success or a failure.
  filename = SCLogPath() .. "/" .. "csf_block.log"
  file = assert(io.open(filename, "a"))
  SCLogInfo("CSF Blocking script started " .. filename)
  count = 0
end


function log(args)
-- Grab data from packet to use in post request
local ipver, srcip, dstip, proto, sp, dp = SCPacketTuple()
-- Grab timestamp
local timestring = SCPacketTimeString()
local class, prio = SCRuleClass()
local sid, rev, gid = SCRuleIds()
local description = SCRuleMsg()
  
  -- Check if alert meets minimum priority threshold and has matching sid
if prio >= config.min_priority and block_sids_lookup[sid] and (dp == 80 or dp == 443) then
  logit(string.format("Alert detected from IP %s on port %d with priority %d and sid %d (%s)", srcip, dp, prio, sid, description))
      block_ip(srcip, description, dp)
  count = count + 1
  end
end

-- Cleans up, and closes the log files
function deinit (args)
  SCLogInfo ("Reports Logged: " .. count);
  io.close(file)
end