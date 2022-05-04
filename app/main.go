package main

import (
    "crypto/sha256"
    "errors"
    "net/http"
    "net/url"
    "strconv"
    "strings"

    "fyne.io/fyne/v2"
    "fyne.io/fyne/v2/app"
    "fyne.io/fyne/v2/container"
    "fyne.io/fyne/v2/data/binding"
    "fyne.io/fyne/v2/layout"
    "fyne.io/fyne/v2/widget"
    "github.com/dbyington/httpio"
    "github.com/dbyington/manifestgo"
)

const (
	windowTitle          = "Manifest Builder"
	manifestBuilderLabel = "Welcome to Manifest Builder"

	defaultWidth  = 1024
	defaultHeight = 800

    footerHeight = 150

	buttonLabel      = "Build"
	inputPlaceHolder = "Enter URL pointing to PKG file here"

    footerText = "hastily made by @dbyington"
    footerURI = "https://github.com/dbyington/manifestgo/app"

    resultText = `Enter a url in the field above and click 'Build' to build a manifestItems json object
Note that the server that serves the supplied URL must support byte range reads for this app to work.`

    noChunking = "none"
	mb = 1 << 20
)

var (
	chunkSizeOptions = []string{"50", "100", "250", "500", noChunking}
)

func main() {

	manifestApp := app.New()
	window := manifestApp.NewWindow(windowTitle)
	label := widget.NewLabel(manifestBuilderLabel)

	// Result field
	result := binding.NewString()
    result.Set(resultText)

    copyBtn := widget.NewButton("Copy To Clipboard", func() {
        manifest, err := result.Get()
        if err != nil {
            result.Set(err.Error())
            return
        }
        window.Clipboard().SetContent(manifest)
    })
    copyBtn.Disable()

    resultField := widget.NewLabelWithData(result)
    resultField.Wrapping = fyne.TextWrapWord

	// Entry fields
	urlEntry := widget.NewEntry()
	urlEntry.SetPlaceHolder(inputPlaceHolder)

    chunkLabel := widget.NewLabel("Select hash chunk size")
	chunkEntry := widget.NewSelect(chunkSizeOptions, nil)
    chunkEntry.SetSelectedIndex(0)

	validateSig := widget.NewCheck("Validate PKG Signer", nil)
	requireDistribution := widget.NewCheck("Require Distribution PKG", nil)

    progress := widget.NewProgressBarInfinite()

    resultContainer := container.NewVBox(resultField)
    resultScroll := container.NewScroll(resultContainer)

    toggleProgress := func(running bool) {
        if running {
            resultContainer.Remove(resultField)
            resultContainer.Add(progress)
            progress.Show()
            progress.Start()
        } else {
            progress.Stop()
            resultContainer.Remove(progress)
            resultContainer.Add(resultField)
        }
    }

	buildButton := makeBuildButton(urlEntry, chunkEntry, validateSig, requireDistribution, toggleProgress, copyBtn, result)
    buildButton.Disable()


    urlEntry.Validator = func(s string) (err error) {
        defer func() {
            if err != nil {
                buildButton.Disable()
                return
            }

            buildButton.Enable()
        }()

        return validateURLString(s)
    }
    
    resetButton := widget.NewButton("Reset", func() {
        copyBtn.Disable()
        urlEntry.SetText("")
        result.Set(resultText)
    })

    optionsContainer := container.NewHBox(chunkLabel, chunkEntry, validateSig, requireDistribution)

    footerURL, err := url.Parse(footerURI)
    if err != nil {
        // This is unexpected, but could happen
        result.Set(err.Error())
    }
    footerLink := widget.NewHyperlink(footerText, footerURL)

    headerContainer := container.NewVBox(label)

    buttonsContainer := container.NewHBox(layout.NewSpacer(), buildButton, layout.NewSpacer(), copyBtn, layout.NewSpacer(), resetButton, layout.NewSpacer())

    entryContainer := container.NewVBox(urlEntry, layout.NewSpacer(), optionsContainer, layout.NewSpacer(), buttonsContainer)

    footerContainer := container.NewVBox(footerLink)
    footerContainer.Resize(fyne.NewSize(defaultWidth, footerHeight))

    topContainer := container.NewVBox(headerContainer, entryContainer)

	mainContainer := container.NewBorder(topContainer, footerContainer, nil, nil, resultScroll)
    window.Resize(fyne.NewSize(defaultWidth, defaultHeight))
	window.SetContent(mainContainer)
	window.ShowAndRun()

}

func makeBuildButton(urlEntry *widget.Entry,
    chunkEntry *widget.Select,
    validateSig, requireDistribution *widget.Check,
    progress func(bool),
    copyBtn *widget.Button,
    result binding.String) *widget.Button{
    return widget.NewButton(buttonLabel, func() {
        copyBtn.Disable()
        progress(true)
        defer progress(false)

        urlEntry.Disable()
        defer urlEntry.Enable()

        if valid := urlEntry.Validate(); valid != nil {
            result.Set(valid.Error())
            return
        }

        chunkSize := 50
        if chunkEntry.Selected != noChunking && chunkEntry.Selected != ""{
            var err error
            chunkSize, err = strconv.Atoi(chunkEntry.Selected)
            if err != nil {
                result.Set(err.Error())
                return
            }
        }

        if chunkEntry.Selected == noChunking {
            chunkSize = -1
        }

        if err := build(urlEntry.Text, int64(chunkSize) * mb, validateSig.Checked, requireDistribution.Checked, result); err != nil {
            result.Set(err.Error())
            return
        }

        copyBtn.Enable()
        urlEntry.SetText("")
    })
}

func build(pkgUrl string, chunkSize int64, validSig, distPkg bool, result binding.String) error {
	if chunkSize == 0 {
		chunkSize = mb * 50
	}

    result.Set("Waiting on pkg read...")

	reader, err := httpio.NewReadAtCloser(
		httpio.WithClient(&http.Client{}),
		httpio.WithURL(pkgUrl),
		httpio.WithHashChunkSize(chunkSize),
	)
	if err != nil {
		return err
	}

	p := manifestgo.NewPackage(reader, sha256.Size, chunkSize)
	if err != nil {
		return err
	}

	if err = p.ReadFromURL(); err != nil {
		return err
	}

	if validSig && !p.HasValidSignature() {
		return errors.New("package does not have a valid signature")
	}

	if distPkg && !p.IsDistribution() {
		return errors.New("package is not a distribution")
	}

	m, err := p.BuildManifest()
	if err != nil {
		return err
	}

	b, err := m.AsJSON(4)
	if err != nil {
		return err
	}

	return result.Set(string(b))
}

func validateURLString(s string) error {
    if len(s) < len("https://.pkg") {
        return errors.New("invalid url")
    }

    u, err := url.Parse(s)
    if err != nil {
        return err
    }

    if u.Scheme != "https" {
        return errors.New("invalid url scheme")
    }

    if !u.IsAbs()  {
        return errors.New("not an absolute url")
    }

    if !strings.HasSuffix(strings.ToLower(s), ".pkg") {
        return errors.New("url does not resolve to a pkg file")
    }

    return nil
}
