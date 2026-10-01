-- Turns a NetAudit webhook event into a CEF:0 line (ArcSight/Splunk/QRadar-compatible).
local SEVERITY = { CRITICAL = 10, HIGH = 8, MEDIUM = 5, LOW = 3 }
local EVENT_SEVERITY = { ROLLED_BACK = 6, REJECTED = 4, APPROVED = 3, REMEDIATION_PROPOSED = 3 }

local BS = "\\"

local function clean(v)
  return (tostring(v or ""):gsub("[\r\n]", " "))
end

-- CEF header fields escape backslash and pipe; extension values escape backslash and equals.
local function header(v)
  return (clean(v):gsub(BS, BS .. BS):gsub("|", BS .. "|"))
end

local function ext(v)
  return (clean(v):gsub(BS, BS .. BS):gsub("=", BS .. "="))
end

function to_cef(tag, timestamp, record)
  local event = record["event_type"] or "UNKNOWN"
  local sev = SEVERITY[tostring(record["severity"] or ""):upper()] or EVENT_SEVERITY[event] or 3
  local name = record["title"] or event
  local fields = {}
  local function add(k, v)
    if v ~= nil then fields[#fields + 1] = k .. "=" .. ext(v) end
  end
  add("externalId", record["audit_run_id"])
  local function labeled(n, label, v)
    if v ~= nil then add("cs" .. n .. "Label", label); add("cs" .. n, v) end
  end
  labeled(1, "controlId", record["control_id"])
  labeled(2, "source", record["source"])
  labeled(3, "preflight", record["preflight_status"])
  add("suser", record["approved_by"] or record["actor"])
  add("msg", record["title"])
  local cef = string.format("CEF:0|NetAudit|NetAudit Engine|1.0|%s|%s|%d|%s",
    header(event), header(name), sev, table.concat(fields, " "))
  return 1, timestamp, { log = cef, event_type = event }
end
