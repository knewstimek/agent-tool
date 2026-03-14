package findtools

// ToolDef는 탐색 대상 도구의 정의이다.
type ToolDef struct {
	Name       string   // 표시 이름: "go", "node", "msbuild"
	Commands   []string // 실행 파일 후보: ["go"], ["msbuild", "MSBuild"]
	Category   string   // 카테고리 키
	EnvVars    []string // 경로 힌트 환경변수: ["GOROOT"], ["JAVA_HOME"]
	EnvSubPath string   // 환경변수 값 + 하위 경로: "bin/go"
	VersionArg string   // 버전 확인 인자: "--version", "version", "-version"
	KnownPaths []string // OS별 알려진 설치 경로 (build tag로 주입)
}

// ToolInfo는 도구 탐색 결과이다.
type ToolInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Version string `json:"version"`
	Source  string `json:"source"` // "env", "path", "known_path", "special"
}

// CategoryLabel은 카테고리 키 → 표시 이름 매핑이다.
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

// CategoryOrder는 출력 시 카테고리 순서이다.
var CategoryOrder = []string{
	"go", "dotnet", "node", "python", "java", "rust",
	"c_cpp", "build", "vcs", "container", "js_runtime",
}

// AllCategories는 유효한 카테고리 키 목록을 반환한다.
func AllCategories() []string {
	return CategoryOrder
}

// Catalog은 모든 도구 정의를 반환한다. OS별 KnownPaths는 catalog_*.go에서 주입.
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

		// Container
		{Name: "docker", Commands: []string{"docker"}, Category: "container",
			VersionArg: "--version"},

		// JS Runtime
		{Name: "bun", Commands: []string{"bun"}, Category: "js_runtime",
			VersionArg: "--version"},
		{Name: "deno", Commands: []string{"deno"}, Category: "js_runtime",
			VersionArg: "--version"},
	}

	// OS별 알려진 경로 주입
	injectKnownPaths(defs)

	return defs
}
