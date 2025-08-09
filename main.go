package main

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	glob "github.com/ryanuber/go-glob"
	"github.com/spf13/cobra"
)

const defaultPGPKey = "hide/hide-private-key.asc"

var manager *secretsManager

func main() {
	cmdGet := &cobra.Command{
		Use:   "get KEYS...",
		Short: "Get secrets from store",
		Args:  cobra.MinimumNArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			for _, key := range args {
				if manager.HasKey(key) {
					fmt.Printf("%s=%q\n", key, manager.Get(key))
				}
			}
		},
	}

	cmdList := &cobra.Command{
		Use:   "list [GLOB PATTERN]",
		Short: "Lists all secrets within store",
		Args:  cobra.MaximumNArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			secrets := manager.List()

			// Sorts keys in list
			keys := make([]string, 0, len(secrets))
			for key := range secrets {
				keys = append(keys, key)
			}
			sort.Strings(keys)

			for _, key := range keys {
				if len(args) == 0 || glob.Glob(args[0], key) {
					fmt.Printf("%s=%q\n", key, secrets[key])
				}
			}
		},
	}

	cmdSet := &cobra.Command{
		Use:   "set KEY=VALUE...",
		Short: "Sets/Updates secrets within store",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			for _, arg := range args {
				key, value, ok := strings.Cut(arg, "=")
				if !ok {
					return fmt.Errorf("invalid arg: %q. expected KEY=VALUE", arg)
				}
				manager.Set(key, value)
				fmt.Printf("SET: %s\n", key)
			}
			return nil
		},
	}

	cmdRemove := &cobra.Command{
		Use:   "remove KEYS...",
		Short: "Removes secrets from store",
		Args:  cobra.MinimumNArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			for _, key := range args {
				if manager.HasKey(key) {
					manager.Remove(key)
					fmt.Printf("REMOVED: %s\n", key)
				}
			}
		},
	}

	cmdPkl := &cobra.Command{
		Use:   "pkl",
		Short: "pkl language binding",
		Args:  cobra.MinimumNArgs(0),
		RunE: func(_ *cobra.Command, args []string) error {
			return startPklReader(manager)
		},
	}

	rootCmd := &cobra.Command{
		Use:       "hide",
		Version:   "0.1.0",
		Short:     "PGP encrypted secrets store",
		ValidArgs: []string{"get", "list", "set", "remove"},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			store, _ := cmd.Flags().GetString("store")
			pgpPrivKeyPath, _ := cmd.Flags().GetString("pgp-private-key")

			m, err := newSecretsManager(store, pgpPrivKeyPath)
			manager = m
			return err
		},
		PersistentPostRunE: func(_ *cobra.Command, _ []string) error {
			return manager.Close()
		},
	}
	rootCmd.AddCommand(cmdGet, cmdList, cmdSet, cmdRemove, cmdPkl)
	rootCmd.PersistentFlags().StringP("store", "s", "hide.enc.env", "path to secrets store")
	rootCmd.PersistentFlags().String("pgp-private-key", getPrivKey(), "PGP private key")
	rootCmd.Execute()
}

func getPrivKey() string {
	if key, ok := os.LookupEnv("HIDE_PGP_PRIV_KEY"); ok {
		return key
	}

	if dataDir, ok := os.LookupEnv("XDG_DATA_HOME"); ok {
		return path.Join(dataDir, defaultPGPKey)
	}

	return path.Join(os.Getenv("HOME"), ".local/share/", defaultPGPKey)
}
