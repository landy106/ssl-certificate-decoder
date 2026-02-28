package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	w := a.NewWindow("SSL Certificate Decoder")
	w.SetContent(makeUI(w))
	w.Resize(fyne.NewSize(630, 650))
	w.ShowAndRun()
}

func makeUI(w fyne.Window) fyne.CanvasObject {
	header := canvas.NewText("SSL Certificate Decoder", theme.Color(theme.ColorNamePrimary))
	header.TextSize = 24
	header.Alignment = fyne.TextAlignCenter

	input := widget.NewEntry()
	input.MultiLine = true
	input.Wrapping = fyne.TextWrapOff
	input.SetPlaceHolder(`Paste your certificate here Or Read from Clipboard.
Your certificate should start with "-----BEGIN CERTIFICATE----- " 
and end with "-----END CERTIFICATE----- "`)

	output := widget.NewEntry()
	output.MultiLine = true
	output.Wrapping = fyne.TextWrapBreak
	output.SetPlaceHolder("Output Result")

	// 让窗口支持拖拽
	w.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
		// 处理拖拽的文件列表
		for _, uri := range uris {
			fileInfo, err := os.Stat(uri.Path())
			if err != nil {
				dialog.ShowError(fmt.Errorf("Read file information failed: %v", err), w)
				continue
			}
			if fileInfo.IsDir() {
				dialog.ShowError(fmt.Errorf("Error: Support CRT file only"), w)
				continue
			}
			content, err := os.ReadFile(uri.Path())
			if err != nil {
				dialog.ShowError(fmt.Errorf("Error: Read file content failed: %v\n", err), w)
				continue
			}
			input.SetText(string(content))

			out := GetCertificateInfo(content)
			output.SetText(fmt.Sprintf("%s\n\nFile name: %s", out, uri.String()))
		}
	})

	openFile := widget.NewButtonWithIcon("Open File", theme.FolderOpenIcon(), func() {
		dialog.ShowFileOpen(func(in fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(fmt.Errorf("Failed to open file: %w", err), w)
				return
			}
			if in == nil || in.URI() == nil {
				return
			}

			certData, err := os.ReadFile(in.URI().Path())
			if err != nil {
				log.Fatal("Error reading certificate file:", err)
				dialog.ShowError(fmt.Errorf("Error reading certificate file: %w", err), w)
				return
			}

			if !strings.Contains(string(certData), "-----BEGIN CERTIFICATE-----") {
				dialog.ShowError(fmt.Errorf("The file content should start with -----BEGIN CERTIFICATE-----"), w)
				return
			}

			// fmt.Println("MimeType:", in.URI().MimeType())
			input.SetText(string(certData))

			out := GetCertificateInfo(certData)
			output.SetText(fmt.Sprintf("%s\n\nFile name: %s", out, in.URI().String()))

		}, w)
	})
	openFile.Importance = widget.HighImportance

	clear := widget.NewButtonWithIcon("clear", theme.ContentClearIcon(), func() {
		output.Text = ""
		output.Refresh()
		input.Text = ""
		input.Refresh()
	})
	clear.Importance = widget.DangerImportance

	decode := widget.NewButtonWithIcon("Decode", theme.MediaPlayIcon(), func() {
		if input.Text == "" {
			input.Text = fyne.CurrentApp().Clipboard().Content()
			input.Refresh()
		}
		out := GetCertificateInfo([]byte(input.Text))
		output.Text = out
		output.Refresh()
	})
	decode.Importance = widget.HighImportance

	copy := widget.NewButtonWithIcon("Cut Result", theme.ContentCutIcon(), func() {
		clipboard := fyne.CurrentApp().Clipboard()
		clipboard.SetContent(output.Text)
		output.Text = ""
		output.Refresh()

		input.Text = ""
		input.Refresh()
	})
	copy.Importance = widget.WarningImportance

	return container.NewBorder(header, nil, nil, nil,
		container.NewGridWithRows(2,
			container.NewBorder(nil, container.NewVBox(decode, container.NewGridWithColumns(3, openFile, copy, clear)), nil, nil, input), output),
	)
}

func GetCertificateInfo(certData []byte) string {
	// Decode the PEM-encoded certificate
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Sprintln("Failed to decode PEM certificate.\nThe content should start with -----BEGIN CERTIFICATE-----.")
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Sprintln("Error parsing X.509 certificate:", err)
	}

	// Construct the certificate information string
	var certificateInfo strings.Builder

	fmt.Fprintf(&certificateInfo, "Common Name: %s\n"+
		"Validity:\n"+
		"\tValid From:\t%s\n"+
		"\tValid To:\t%s\n"+
		"Subject Alternative Names:\n",
		cert.Subject.CommonName,
		cert.NotBefore.UTC().Format(time.DateTime),
		cert.NotAfter.UTC().Format(time.DateTime))

	for _, name := range cert.DNSNames {
		fmt.Fprintf(&certificateInfo, "\t- %s\n", name)
	}

	fmt.Fprintf(&certificateInfo,
		"Serial Number: %s\n"+
			"Issuer: %s\n",
		cert.SerialNumber.String(),
		cert.Issuer.String())

	return certificateInfo.String()
}
