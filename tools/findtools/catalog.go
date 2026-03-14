package findtools

// ToolDef defines a tool to discover.
type ToolDef struct {
	Name       string   // Display name: "go", "node", "msbuild"
	Commands   []string // Executable candidates: ["go"], ["msbuild", "MSBuild"]
	Category   string   // Category key
	EnvVars    []string // Path hint environment variables: ["GOROOT"], ["JAVA_HOME"]
	EnvSubPath string   // Environment variable value + sub-path: "bin/go"
	VersionArg string   // Version check argument: "--version", "version", "-version"
	KnownPaths []string // Known installation paths per OS (injected via build tags)
}

// ToolInfo represents a tool discovery result.
type ToolInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Version string `json:"version"`
	Source  string `json:"source"` // "env", "path", "known_path", "special"
}

// CategoryLabel maps category keys to display names.
var CategoryLabel = map[string]string{
	"go":         "Go",
	"dotnet":     ".NET",
	"node":       "Node.js",
	"python":     "Python",
	"java":       "Java",
	"rust":       "Rust",
	"c_cpp":      "C/C++",
	"build":      "Build Tools",
	"vcs":        "Version Control",
	"container":  "Container",
	"js_runtime": "JS Runtime",
}

// CategoryOrder defines the display order of categories.
var CategoryOrder = []string{
	"go", "dotnet", "node", "python", "java", "rust",
	"c_cpp", "build", "vcs", "container", "js_runtime",
}

// AllCategories returns the list of valid category keys.
func AllCategories() []string {
	return CategoryOrder
}

// Catalog returns all tool definitions. OS-specific KnownPaths are injected from catalog_*.go.
func Catalog() []ToolDef {
	defs := []ToolDef{
		// Go
		{Name: "go", Commands: []string{"go"}, Category: "go",
			EnvVars: []string{"GOROOT"}, EnvSubPath: "bin/go", VersionArg: "version"},

		// .NET
		{Name: "dotnet", Commands: []string{"dotnet"}, Category: "dotnet",
			EnvVars: []string{"DOTNET_ROOT"}, EnvSubPath: "dotnet", VersionArg: "--version"},
		{Name: "msbuild", Commands: []string{"msbuild", "MSBuild"}, Category: "dotnet",
			VersionArg: "-version"},

		// Node.js
		{Name: "node", Commands: []string{"node"}, Category: "node",
			VersionArg: "--version"},
		{Name: "npm", Commands: []string{"npm"}, Category: "node",
			VersionArg: "--version"},
		{Name: "npx", Commands: []string{"npx"}, Category: "node",
			VersionArg: "--version"},

		// Python
		{Name: "python3", Commands: pythonCommands(), Category: "python",
			VersionArg: "--version"},
		{Name: "pip", Commands: pipCommands(), Category: "python",
			VersionArg: "--version"},

		// Java
		{Name: "java", Commands: []string{"java"}, Category: "java",
			EnvVars: []string{"JAVA_HOME"}, EnvSubPath: "bin/java", VersionArg: "-version"},
		{Name: "javac", Commands: []string{"javac"}, Category: "java",
			EnvVars: []string{"JAVA_HOME"}, EnvSubPath: "bin/javac", VersionArg: "-version"},

		// Rust
		{Name: "cargo", Commands: []string{"cargo"}, Category: "rust",
			EnvVars: []string{"CARGO_HOME"}, EnvSubPath: "bin/cargo", VersionArg: "--version"},
		{Name: "rustc", Commands: []string{"rustc"}, Category: "rust",
			VersionArg: "--version"},
		{Name: "rustup", Commands: []string{"rustup"}, Category: "rust",
			EnvVars: []string{"CARGO_HOME"}, EnvSubPath: "bin/rustup", VersionArg: "--version"},

		// C/C++
		{Name: "gcc", Commands: []string{"gcc"}, Category: "c_cpp",
			VersionArg: "--version"},
		{Name: "g++", Commands: []string{"g++"}, Category: "c_cpp",
			VersionArg: "--version"},
		{Name: "clang", Commands: []string{"clang"}, Category: "c_cpp",
			VersionArg: "--version"},
		{Name: "clang++", Commands: []string{"clang++"}, Category: "c_cpp",
			VersionArg: "--version"},

		// Build Tools
		{Name: "cmake", Commands: []string{"cmake"}, Category: "build",
			VersionArg: "--version"},
		{Name: "make", Commands: []string{"make"}, Category: "build",
			VersionArg: "--version"},
		{Name: "ninja", Commands: []string{"ninja"}, Category: "build",
			VersionArg: "--version"},

		// VCS
		{Name: "git", Commands: []string{"git"}, Category: "vcs",
			VersionArg: "--version"},
		{Name: "gh", Commands: []string{"gh"}, Category: "vcs",
			VersionArg: "--version"},

		// Container
		{Name: "docker", Commands: []string{"docker"}, Category: "container",
			VersionArg: "--version"},

		// JS Runtime
		{Name: "bun", Commands: []string{"bun"}, Category: "js_runtime",
			VersionArg: "--version"},
		{Name: "deno", Commands: []string{"deno"}, Category: "js_runtime",
			VersionArg: "--version"},
	}

	// Inject OS-specific known paths
	injectKnownPaths(defs)

	return defs
}
