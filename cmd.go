package main

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	prompt "github.com/c-bata/go-prompt"
	"github.com/spf13/cobra"
)

type globalFlags struct {
	profile string
	region  string
}

func NewRootCmd() *cobra.Command {
	f := &globalFlags{}
	cmd := &cobra.Command{
		Use:   "kms",
		Short: "kms is encrypt/decrypt tool using AWS KMS",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.PersistentFlags().StringVarP(&f.profile, "profile", "p", "default", "profile")
	cmd.PersistentFlags().StringVarP(&f.region, "region", "r", "", "region")
	cmd.AddCommand(NewEncryptCmd(f), NewDecryptCmd(f))
	return cmd
}

func NewDecryptCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "decrypt",
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, err := session.NewSessionWithOptions(session.Options{
				Profile: gf.profile,
				Config: aws.Config{
					Region: &gf.region,
				},
			})
			if err != nil {
				return err
			}

			result := prompt.Input("blob: ", func(t prompt.Document) []prompt.Suggest {
				return []prompt.Suggest{}
			})
			k := kms.New(sess)

			r, err := base64.StdEncoding.DecodeString(result)
			if err != nil {
				return err
			}
			o, err := k.Decrypt(&kms.DecryptInput{
				CiphertextBlob: r,
			})
			if err != nil {
				return err
			}
			fmt.Println(string(o.Plaintext))
			return nil
		},
	}
	return cmd

}

func NewEncryptCmd(gf *globalFlags) *cobra.Command {
	encryptFlags := struct {
		keyId string
	}{}
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "encrypt",
		RunE: func(cmd *cobra.Command, args []string) error {
			if encryptFlags.keyId == "" {
				return errors.New("key-id is not specified")
			}
			sess, err := session.NewSessionWithOptions(session.Options{
				Profile: gf.profile,
				Config: aws.Config{
					Region: &gf.region,
				},
			})
			if err != nil {
				return err
			}

			result := prompt.Input("text: ", func(t prompt.Document) []prompt.Suggest {
				return []prompt.Suggest{}
			})
			k := kms.New(sess)
			o, err := k.Encrypt(&kms.EncryptInput{
				KeyId:     &encryptFlags.keyId,
				Plaintext: []byte(result),
			})
			if err != nil {
				return err
			}
			r := base64.StdEncoding.EncodeToString(o.CiphertextBlob)
			fmt.Println(r)
			return nil
		},
	}
	cmd.Flags().StringVarP(&encryptFlags.keyId, "key-id", "k", "", "kms key-id")
	return cmd
}
