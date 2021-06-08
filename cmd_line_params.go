package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

type CliParams struct {
	dev    []string
	server string
	port   uint16

	auto   bool
	skb    bool
	native bool
	unload bool

	// 对存量，新增，删除，查看规则有影响
	lastRuleFixed   bool
	lastRuleAccept  bool
	lastRuleDisplay bool

	conf string
}

var opt CliParams

const colorName = "\033[1;34mX\033[1;0m\033[1;31mD\033[0m\033[1;33mP\033[0m \033[1;34mA\033[0m\033[1;32mC\033[0m\033[1;31mL\033[0m"

// 定义命令行参数对应的变量，变量都是指针类型
var rootCmd = &cobra.Command{
	Version: "0.0.10",
	Use:     "./xdp_acl -D netDevName[,netDevName...]",
	Example: "./xdp_acl -D eth1\n./xdp_acl -D eth1,eth2\n./xdp_acl -D eth1 -S\n./xdp_acl -D eth1 --last-rule-fixed=false",
	Short:   colorName + " is a very high performance ACL",
	// Long: `A Fast and Flexible Static Site Generator built with
	// 			  love by spf13 and friends in Go.
	// 			  Complete documentation is available at http://hugo.spf13.com`,
	Run: func(cmd *cobra.Command, args []string) {
		// 此处也可以获取到参数值
		// tog, err := cmd.Flags().GetBool("tog")
		// fmt.Println("tog=", tog, " err=", err)
	},
}

func cmdLineInputParamsInit() {
	rootCmd.Flags().StringSliceVarP(&(opt.dev), "dev", "D", []string{}, "Input Your Net Device Name (multi dev has to be separated by ',')")

	rootCmd.Flags().BoolVarP(&(opt.auto), "auto-mode", "A", true, "Auto-detect SKB or Native mode")
	rootCmd.Flags().BoolVarP(&(opt.skb), "skb-mode", "S", false, "Load XDP program in SKB mode")
	rootCmd.Flags().BoolVarP(&(opt.native), "native-mode", "N", false, "Load XDP program in Native mode")

	rootCmd.Flags().BoolVarP(&(opt.unload), "unload", "U", false, "Unload XDP program")

	rootCmd.Flags().BoolVarP(&(opt.lastRuleFixed), "last-rule-fixed", "", true, "Last rule is fixed or can be set")
	rootCmd.Flags().BoolVarP(&(opt.lastRuleAccept), "last-rule-accept", "", true, "Set the last rule strategy to be accept or drop")
	rootCmd.Flags().BoolVarP(&(opt.lastRuleDisplay), "last-rule-display", "", false, "Display or hide the last rule")

	rootCmd.Flags().StringVarP(&(opt.conf), "conf", "c", "acl.json", "config file")
	rootCmd.Flags().StringVarP(&(opt.server), "server", "s", "0.0.0.0", "Input Your server host")
	rootCmd.Flags().Uint16VarP(&(opt.port), "port", "p", 9090, "Input Your server port")

	rootCmd.Flags().SortFlags = false

	// must required
	rootCmd.MarkFlagRequired("dev")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	if len(opt.dev) == 0 {
		os.Exit(1)
	}

	if (opt.unload && opt.native && opt.skb) || (opt.unload && opt.native) || (opt.unload && opt.skb) || (opt.native && opt.skb) {
		fmt.Println("--skb-mode and --native-mode and --unload can not be set at the same time\nrun \"./xdp_acl -h\" for help")
		os.Exit(1)
	}

	if opt.skb {
		XDP_FLAGS &= (^XDP_FLAGS_MODES)
		XDP_FLAGS |= XDP_FLAGS_SKB_MODE

		fmt.Println("Load XDP in SKB mode")
	} else if opt.native {
		XDP_FLAGS &= (^XDP_FLAGS_MODES)
		XDP_FLAGS |= XDP_FLAGS_DRV_MODE

		fmt.Println("Load XDP in Native mode")
	} else if opt.unload {

		for i := 0; i < len(opt.dev); i++ {
			if link, err := netlink.LinkByName(opt.dev[i]); err != nil {
				fmt.Println(err.Error(), "; Please check your input device name: 「", opt.dev[i], "」 is right.")
			} else {
				XDP_FLAGS &= (^XDP_FLAGS_MODES)
				XDP_FLAGS |= XDP_FLAGS_SKB_MODE
				unloadXDP(link)

				XDP_FLAGS &= (^XDP_FLAGS_MODES)
				XDP_FLAGS |= XDP_FLAGS_DRV_MODE
				unloadXDP(link)
			}
		}

		fmt.Println("Unload XDP from dev:", opt.dev)

		os.Exit(1)
	} else {
		// XDP_FLAGS = XDP_FLAGS_AUTO_MODE

		XDP_FLAGS &= (^XDP_FLAGS_MODES)
		fmt.Println("Load XDP in AUTO mode")
	}

	fmt.Println("Welcome to " + colorName)
}
