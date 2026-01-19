local function shallow_copy(t)
  local copy = {}
  for k, v in pairs(t) do copy[k] = v end
  return copy
end

local function empty_if_missing(v)
  return v ~= nil and v or ""
end

function normalize(tag, ts, record)
  -- Skip records with empty or missing event type
  if record["ev"] == nil or record["ev"] == "" then
    return -1, 0, 0
  end

  -- Convert Fluent Bit timestamp (Unix epoch) to ClickHouse DateTime64 format
  -- ts is a number like 1737335734.508, convert to "2026-01-20 01:55:34.508"
  local sec = math.floor(ts)
  local msec = math.floor((ts - sec) * 1000)
  record["ts"] = os.date("!%Y-%m-%d %H:%M:%S", sec) .. string.format(".%03d", msec)

  -- Copy full record to log field for flexible querying (before normalization)
  record["log"] = shallow_copy(record)

  -- Ensure tags array is not empty (empty Lua table {} serializes as JSON object, not array)
  if record["tags"] == nil or #record["tags"] == 0 then
    record["tags"] = { "" }
  end

  record["user"] = empty_if_missing(record["user"])
  record["db"] = empty_if_missing(record["db"])
  record["cmd"] = empty_if_missing(record["cmd"])
  record["error"] = empty_if_missing(record["error"])
  record["source"] = empty_if_missing(record["source"])

  record["bytesInTotal"] = record["bytesInTotal"] or 0
  record["bytesOutTotal"] = record["bytesOutTotal"] or 0

  return 1, ts, record
end
