package ssh

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"agent-tool/common"
	"agent-tool/internal/vault"
)

func ImportLegacyProfiles(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("vault import-ssh", flag.ContinueOnError)
	suffix := flags.String("suffix", "-vault", "Suffix for encrypted copy names; legacy names remain usable")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *suffix == "" || *suffix != strings.TrimSpace(*suffix) {
		return fmt.Errorf("supply a nonempty --suffix to keep the original profile names usable")
	}
	profiles, _, err := readLocalConnectionProfiles()
	if err != nil {
		return fmt.Errorf("cannot read the legacy SSH profile file")
	}
	if len(profiles) == 0 {
		return fmt.Errorf("no legacy SSH profiles found")
	}
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	slices.Sort(names)
	records := make([]vault.SSHImportRecord, 0, len(profiles))
	for i, name := range names {
		p := profiles[name]
		newName := name + *suffix
		if _, exists := profiles[newName]; exists {
			return fmt.Errorf("encrypted name for source entry %d conflicts with a legacy name; choose another --suffix", i+1)
		}
		port, validPort := common.FlexInt(p.Port)
		jumpPort, validJumpPort := common.FlexInt(p.JumpPort)
		if !validPort || !validJumpPort || name != strings.TrimSpace(name) || name == "" {
			return fmt.Errorf("invalid name or port in source entry %d", i+1)
		}
		keyFile := expandTilde(strings.TrimSpace(p.KeyFile))
		jumpKeyFile := expandTilde(strings.TrimSpace(p.JumpKeyFile))
		if (keyFile != "" && !filepath.IsAbs(keyFile)) || (jumpKeyFile != "" && !filepath.IsAbs(jumpKeyFile)) {
			return fmt.Errorf("source entry %d has a relative private key path; resolve it before importing", i+1)
		}
		records = append(records, vault.SSHImportRecord{
			Profile: vault.Profile{Kind: vault.SSH, Name: newName, Metadata: p.searchMetadata},
			Credentials: vault.Credentials{
				Host: p.Host, Port: port, User: p.User, Password: p.Password,
				Passphrase: p.Passphrase, UseAgent: common.FlexBool(p.UseAgent) || (p.Password == "" && keyFile == ""),
				HostKeyCheck: p.HostKeyCheck, RemoteRoot: p.RemoteRoot, RemoteShell: p.RemoteShell,
				JumpHost: p.JumpHost, JumpPort: jumpPort, JumpUser: p.JumpUser, JumpPassword: p.JumpPassword, JumpPassphrase: p.JumpPassphrase,
			},
			KeyFile: keyFile, JumpKeyFile: jumpKeyFile,
		})
	}
	return vault.ImportSSH(ctx, records)
}
