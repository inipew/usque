package cmd

import (
	"log"
	"sync"

	"github.com/Diniboy1123/usque/config"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "usque",
	Short: "Usque Warp CLI",
	Long:  "An unofficial Cloudflare Warp CLI that uses the MASQUE protocol and exposes the tunnel as various different services.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			log.Fatalf("Failed to get config path: %v", err)
		}

		if configPath != "" {
			if err := config.LoadConfig(configPath); err != nil {
				log.Printf("Config file not found: %v", err)
				log.Printf("You may only use the register command to generate one.")
			}
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		var wg sync.WaitGroup
		var started bool

		if config.AppConfig.Socks.Enabled {
			wg.Add(1)
			started = true
			go func() {
				defer wg.Done()
				socksCmd.Run(socksCmd, []string{})
			}()
		}

		if config.AppConfig.HTTP.Enabled {
			wg.Add(1)
			started = true
			go func() {
				defer wg.Done()
				httpProxyCmd.Run(httpProxyCmd, []string{})
			}()
		}

		if !started {
			cmd.Println("No services enabled in config")
			return
		}

		wg.Wait()
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", "config.json", "config file (default is config.json)")
}
