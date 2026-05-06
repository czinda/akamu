-- mermaid-filter.lua
-- Pandoc Lua filter: render mermaid code blocks as PNG images.
-- Used by the pandoc/pdf backend (HTML backend uses mermaid.js in-browser).
--
-- Requires mmdc from @mermaid-js/mermaid-cli, either in PATH or in
-- node_modules/.bin/ next to this filter file.

local tmpdir    = nil
local mmdc      = nil
local mmd_cfg   = nil   -- path to mermaid-pdf-config.json
local counter   = 0

local function script_dir()
    return PANDOC_SCRIPT_FILE:match("(.*)/[^/]*$") or "."
end

local function find_mmdc()
    -- Prefer system mmdc if present.
    local h = io.popen("which mmdc 2>/dev/null")
    local s = h:read("*a"):gsub("%s+$", "")
    h:close()
    if s ~= "" then return s end

    -- Fall back to local node_modules.
    local local_bin = script_dir() .. "/node_modules/.bin/mmdc"
    local f = io.open(local_bin, "r")
    if f then f:close(); return local_bin end

    return nil
end

local chromium_candidates = {
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
}

local function find_chromium()
    for _, path in ipairs(chromium_candidates) do
        local f = io.open(path, "r")
        if f then f:close(); return path end
    end
    return nil
end

-- Write a temporary puppeteer config pointing at the system browser.
local function make_puppeteer_cfg(dir, chromium_path)
    if not chromium_path then return nil end
    local cfg_path = dir .. "/puppeteer.json"
    local f = io.open(cfg_path, "w")
    if not f then return nil end
    f:write('{"executablePath":"' .. chromium_path .. '","args":["--no-sandbox","--disable-setuid-sandbox"]}\n')
    f:close()
    return cfg_path
end

local function init()
    if tmpdir then return end

    local base = os.tmpname()
    os.remove(base)
    tmpdir = base .. "-mermaid"
    os.execute("mkdir -p " .. tmpdir)

    mmdc = find_mmdc()
    if not mmdc then
        io.stderr:write("[mermaid-filter] mmdc not found; install @mermaid-js/mermaid-cli\n")
        mmdc = ""
    end

    -- Pick up the theme config sitting next to this filter file.
    local cfg = script_dir() .. "/mermaid-pdf-config.json"
    local f = io.open(cfg, "r")
    if f then f:close(); mmd_cfg = cfg end
end

function CodeBlock(block)
    if not block.classes:includes("mermaid") then
        return nil
    end

    init()
    if mmdc == "" then return nil end

    counter = counter + 1
    local infile  = tmpdir .. "/diagram-" .. counter .. ".mmd"
    local outfile = tmpdir .. "/diagram-" .. counter .. ".png"

    local f = io.open(infile, "w")
    if not f then return nil end
    f:write(block.text)
    f:close()

    local chromium  = find_chromium()
    local pcfg_path = make_puppeteer_cfg(tmpdir, chromium)

    local cmd = '"' .. mmdc .. '"'
              .. " -i " .. infile
              .. " -o " .. outfile
              .. " -b white"
    if mmd_cfg then
        cmd = cmd .. ' -c "' .. mmd_cfg .. '"'
    end
    if pcfg_path then
        cmd = cmd .. ' --puppeteerConfigFile "' .. pcfg_path .. '"'
    end
    cmd = cmd .. " 2>/dev/null"

    local ok = os.execute(cmd)

    local img = io.open(outfile, "r")
    if not (ok and img) then
        io.stderr:write("[mermaid-filter] diagram " .. counter .. " failed to render\n")
        if img then img:close() end
        return nil
    end
    img:close()

    return pandoc.Para({ pandoc.Image({}, outfile) })
end
