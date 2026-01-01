package utils

import (
	"github.com/fatih/color"
)

// PrintBanner displays the ApkSentinel ASCII banner.
func PrintBanner() {
	banner := `
    ___        __   _____             _   _             _ 
   / _ \      |  | /  ___|           | | (_)           | |
  / /_\ \_ __ |  | \ '---.  ___ _ __ | |_ _ _ __   ___| |
  |  _  | '_ \|  |  '---. \/ _ \ '_ \| __| | '_ \ / _ \ |
  | | | | |_) |  | /\__/ /  __/ | | | |_| | | | |  __/ |
  \_| |_/ .__/|__| \____/ \___|_| |_|\__|_|_| |_|\___|_|
        | |                                               
        |_|                                               
    `
	color.Cyan(banner)
	color.Yellow("    ApkSentinel - APK Static Analysis & Secret Scanner")
	color.Yellow("    Developed by Ismail Tasdelen (@ismailtsdln)\n")
}

// Info prints an informational message.
func Info(format string, a ...interface{}) {
	color.Blue("[*] "+format, a...)
}

// Success prints a success message.
func Success(format string, a ...interface{}) {
	color.Green("[+] "+format, a...)
}

// Warning prints a warning message.
func Warning(format string, a ...interface{}) {
	color.Yellow("[!] "+format, a...)
}

// Error prints an error message.
func Error(format string, a ...interface{}) {
	color.Red("[x] "+format, a...)
}
