// Package cmd
/*
Copyright © 2021 Don Byington don!dbyington.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
    "crypto/sha256"
    "errors"
    "fmt"
    "net/http"
    "os"

    "github.com/dbyington/httpio"
    "github.com/spf13/cobra"

    "github.com/dbyington/manifestgo"
)

const mb = 1 << 20

var (
    chunkSize         int64
    pkgFile           string
    pkgUrl            string
    plistOutput       bool
    validSig, distPkg bool
)

var ErrPkgNotExist = os.ErrNotExist

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
    Use:   "manifestgo",
    Short: "Easily create a package manifest",
    Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
    // Uncomment the following line if your bare application
    // has an action associated with it:
    RunE: func(cmd *cobra.Command, args []string) error {
        var (
            p   *manifestgo.Package
            m   *manifestgo.Manifest
            err error
        )

        if pkgFile != "" {
            if _, err = os.Stat(pkgFile); err != nil{
                if os.IsNotExist(err) {
                    return ErrPkgNotExist
                } else {
                    cmd.Printf("os stat returned an error: %s\n", err)
                    return err
                }
            }

            p, err = manifestgo.ReadPkgFile(pkgFile)
            if err != nil {
                cmd.Printf("read pkg file returned an error: %s\n", err)
                return err
            }
            p.URL = "NONE"
        } else if pkgUrl != "" {
            reader, err := httpio.NewReadAtCloser(
                httpio.WithClient(&http.Client{}),
                httpio.WithURL(pkgUrl),
                httpio.WithHashChunkSize(chunkSize),
            )
            if err != nil {
                return err
            }

            p = manifestgo.NewPackage(reader, sha256.Size, chunkSize)
            if err != nil {
                return err
            }

            if err = p.ReadFromURL(); err != nil {
                return err
            }
        } else {
            return ErrPkgNotExist
        }

        if validSig && !p.HasValidSignature() {
            return errors.New("package does not have a valid signature")
        }

        if distPkg && !p.IsDistribution() {
            return errors.New("package is not a distribution")
        }

        m, err = p.BuildManifest()
        if err != nil {
            return err
        }

        b, err := m.AsJSON(4)
        if err != nil {
            return err
        }
        fmt.Println(string(b))
        return nil
    },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
    cobra.CheckErr(rootCmd.Execute())
}

func init() {
    rootCmd.PersistentFlags().Int64Var(&chunkSize, "chunksize", 100, "checksum chunk size in MB")
    rootCmd.PersistentFlags().StringVar(&pkgFile, "pkg", "", "pkg file")
    rootCmd.PersistentFlags().StringVar(&pkgUrl, "url", "", "pkg url")
    rootCmd.PersistentFlags().BoolVar(&distPkg, "distribution", true, "distribution, require pkg be a distributions package")
    rootCmd.PersistentFlags().BoolVar(&plistOutput, "plistOutput", false, "plistOutput, dump the result as a plistOutput file")
    rootCmd.PersistentFlags().BoolVar(&validSig, "validSignature", true, "validSignature, require the pkg to have been signed with a valid certificate")
}

