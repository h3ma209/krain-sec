package utils

import (
	"fmt"

	"github.com/rivo/tview"
	// "pcap"
)

func Banner() {
	fmt.Println(`
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓███████▓▒░   ░▒▓██████▓▒░  ░▒▓█▓▒░ ░▒▓███████▓▒░               ░▒▓███████▓▒░ ░▒▓████████▓▒░  ░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░             ░▒▓█▓▒░        ░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░             ░▒▓█▓▒░        ░▒▓█▓▒░        ░▒▓█▓▒░        
░▒▓███████▓▒░  ░▒▓███████▓▒░  ░▒▓████████▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░              ░▒▓██████▓▒░  ░▒▓██████▓▒░   ░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░                    ░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░                    ░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░             ░▒▓███████▓▒░  ░▒▓████████▓▒░  ░▒▓██████▓▒░  
	`)
	fmt.Println("WELCOME TO KRIAN - SEC")
}

func SetNewNetworkPacketTableCell(packetTable *tview.Table, row int, id int, timestamp, srcIP, dstIP, protocol, length, info string) {
	packetTable.SetCell(row, 0, tview.NewTableCell(fmt.Sprintf("%d", id)).SetTextColor(tview.Styles.SecondaryTextColor))
	packetTable.SetCell(row, 1, tview.NewTableCell(timestamp).SetTextColor(tview.Styles.TertiaryTextColor))
	packetTable.SetCell(row, 2, tview.NewTableCell(srcIP).SetTextColor(tview.Styles.PrimaryTextColor))
	packetTable.SetCell(row, 3, tview.NewTableCell(dstIP).SetTextColor(tview.Styles.PrimaryTextColor))
	packetTable.SetCell(row, 4, tview.NewTableCell(protocol).SetTextColor(tview.Styles.ContrastSecondaryTextColor))
	packetTable.SetCell(row, 5, tview.NewTableCell(length).SetTextColor(tview.Styles.TertiaryTextColor))
	packetTable.SetCell(row, 6, tview.NewTableCell(info).SetTextColor(tview.Styles.ContrastBackgroundColor))
}
