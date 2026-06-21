## Context

`config.Discover()` currently calls `os.UserHomeDir()` and constructs all config paths relative to home. It returns the first found config per tool (breaks after first match). This means even if a tool supports both global and project configs, only the global one is ever discovered.

Most AI tools support project-scoped MCP configs. The standard pattern is: check for a project-level config file in the current working directory (or walking upward), then fall back to the global config. Some tools merge both (project overrides global per-server), others use project exclusively when present.

The `Discover()` function needs to accept a starting directory, walk upward to find project-scoped configs per tool, and merge results with global configs using clear precedence rules.

## Goals / Non-Goals

**Goals:**
- `Discover()` accepts an optional `cwd string` parameter (empty = no project discovery, current behavior)
- Walk from `cwd` upward to filesystem root, checking each directory for project-scoped config files
- For each tool, discover both global and project configs; merge with project taking precedence per server name
- New `--project-dir` CLI flag to specify the starting directory (defaults to cwd)
- New `--no-project-config` flag to disable project-scoped discovery entirely
- `ServerEntry` gains a `Scope` field (`"global"` | `"project"`)
- `Config` gains a `Scope` field to indicate where the config was found

**Non-Goals:**
- Automatic monorepo/workspace detection
- `.gitignore`-aware config skipping
- Recursive subdirectory scanning
- Network-mounted project configs

## Decisions

**Decision: Walk upward, stop at filesystem root**
- Rationale: Same behavior as git's repository discovery. Walk from cwd to `/`, checking each ancestor. Stop when we find a config or hit root. Simpler than configurable depth limits for v1.
- Alternative: Configurable max depth — rejected as premature optimization. We can add `--project-max-depth` later if needed.

**Decision: Project configs merged with global; project wins on same server name**
- Rationale: If a project `.mcp.json` defines a server `"my-db"` and the global config also defines `"my-db"`, the project definition is used. This matches how Claude Code and Cursor handle overrides. Non-conflicting servers from both sources are included.
- Server identity key: `(server.Name, config.Tool)` — same name across different tools is NOT a conflict.

**Decision: `Discover("")` preserves existing behavior**
- Rationale: When `--no-project-config` is set (or cwd is empty), the function behaves identically to the current implementation. Zero breaking changes.

**Decision: Walk stops at first config-bearing directory per tool**
- Rationale: If `.mcp.json` is found at both `/project/.mcp.json` and `/project/subdir/.mcp.json`, only the closest one to cwd is used. This prevents indefinite upward scanning and matches Claude Code's behavior.

## Risks / Trade-offs

- **Performance on deep directory trees** → Mitigation: Walk stops at first found config per tool. Deep trees with no config files anywhere would scan to root, but stat calls on directories are cheap. A 50-level tree takes ~50 stat calls per tool — under 1ms total.
- **Unexpected project configs could mask global configs** → Mitigation: Each result's `Scope` field is visible in the output. Users can see exactly which config source produced each server entry. `--no-project-config` is always available.
