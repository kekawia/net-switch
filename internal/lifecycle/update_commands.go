package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kekawia/net-switch/internal/desktop"
	"github.com/kekawia/net-switch/internal/updates"
)

func updateCommand(args []string) error {
	command := args[0]
	if command == "update-check-root" {
		if len(args) != 1 {
			return errors.New("update-check-root takes no arguments")
		}
		return updates.CheckProductionRoot()
	}
	flags := flag.NewFlagSet("netswitchctl "+command, flag.ContinueOnError)
	apply := flags.Bool("apply", false, "apply the accepted, protected update operation")
	request := flags.Bool("request", false, "ask the enrolled owner's Control service to check and update")
	statusOnly := flags.Bool("status", false, "read current update progress")
	data := flags.String("data", DefaultData(), "protected machine store")
	operation := flags.String("operation", "", "accepted update operation")
	appDir := flags.String("app-dir", "", "versioned installation root")
	version := flags.String("version", "", "release version")
	architecture := flags.String("arch", "", "x64 or arm64")
	installer := flags.String("installer", "", "installer file to hash or keep")
	keyPath := flags.String("key", "", "unencrypted Minisign secret key file")
	keyEnv := flags.String("key-env", "", "environment variable containing the release signing key")
	publicPath := flags.String("public-key", "", "public key output, or release public key to authorize")
	rootPath := flags.String("root-public-key", "", "offline root public key for signing-tool verification")
	statementPath := flags.String("key-statement", "", "root-signed release key statement")
	manifestPath := flags.String("manifest", "", "signed manifest to verify")
	current := flags.String("current", "", "installed version for offline verification")
	output := flags.String("out", "", "signed JSON output path; its signature uses .minisig")
	expires := flags.String("expires", "", "required expiry in RFC3339 UTC")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected signing command arguments")
	}
	switch command {
	case "update":
		if *request || *statusOnly {
			if *apply || (*request && *statusOnly) {
				return errors.New("choose exactly one update action")
			}
			return requestControlUpdate(*version, *statusOnly)
		}
		if !*apply || *operation == "" {
			return errors.New("usage: netswitchctl update --apply --operation <accepted operation> [--data <store>]")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		return ApplyUpdate(ctx, *data, *operation)
	case "update-verify-manifest":
		return verifyUpdateCommand(*rootPath, *statementPath, *manifestPath, *current, *architecture, *installer)
	case "update-keep":
		if *appDir == "" || *installer == "" || *version == "" {
			return errors.New("update-keep requires --app-dir, --version and --installer")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		return KeepUpdateInstaller(ctx, *appDir, *version, *installer, *data, *operation)
	case "update-keygen":
		if *keyPath == "" || *publicPath == "" || *keyEnv != "" {
			return errors.New("update-keygen requires --key and --public-key; existing files are never replaced")
		}
		public, secret, err := updates.GenerateKeyPair()
		if err != nil {
			return err
		}
		if err := createUpdateToolFile(*keyPath, []byte(secret), true); err != nil {
			return err
		}
		if err := createUpdateToolFile(*publicPath, []byte(public), false); err != nil {
			return errors.Join(err, os.Remove(*keyPath))
		}
		fmt.Print(public)
		return nil
	}
	if *output == "" {
		return errors.New("signing requires --out")
	}
	if command != "update-sign-manifest" && *keyEnv != "" {
		return errors.New("--key-env is only for the online release signing key")
	}
	secret, err := loadUpdateSigningSecret(*keyPath, *keyEnv)
	if err != nil {
		return err
	}
	defer clear(secret)
	now := time.Now().UTC()
	deadline, err := time.Parse(time.RFC3339, *expires)
	if err != nil || !deadline.After(now) {
		return errors.New("--expires must be a future RFC3339 timestamp")
	}
	switch command {
	case "update-issue-release-key":
		if *publicPath == "" {
			return errors.New("issuing a release key requires --public-key")
		}
		public, err := readUpdateToolFile(*publicPath, 16384)
		if err != nil {
			return err
		}
		statement := updates.ReleaseKeyStatement{Purpose: "netswitch-release-signing", PublicKey: string(public), IssuedAt: now, ExpiresAt: deadline}
		raw, err := json.MarshalIndent(statement, "", "  ")
		if err != nil {
			return err
		}
		signature, err := updates.SignMinisign(string(secret), raw, "Net Switch release signing key")
		if err != nil {
			return err
		}
		root, err := updates.PublicKeyFromSecret(string(secret))
		if err != nil {
			return err
		}
		if _, err := updates.VerifyReleaseKey(root, raw, signature, now); err != nil {
			return err
		}
		return writeSignedUpdateOutput(*output, raw, signature)
	case "update-sign-manifest":
		if *statementPath == "" || *installer == "" || !updates.CanonicalVersion(*version) || (*architecture != "x64" && *architecture != "arm64") {
			return errors.New("manifest signing requires --key-statement, --installer, --version and --arch")
		}
		root := updates.RootPublicKey
		if *rootPath != "" {
			b, err := readUpdateToolFile(*rootPath, 16384)
			if err != nil {
				return err
			}
			root = string(b)
		}
		statement, err := readUpdateToolFile(*statementPath, updates.MaxMetadataSize)
		if err != nil {
			return err
		}
		keySignature, err := readUpdateToolFile(*statementPath+".minisig", updates.MaxMetadataSize)
		if err != nil {
			return err
		}
		key, err := updates.VerifyReleaseKey(root, statement, keySignature, now)
		if err != nil {
			return err
		}
		// Signing an empty payload with the supplied key and checking against the
		// authorized public key also handles its standard two-line file format.
		proof, err := updates.SignMinisign(string(secret), nil, "key possession")
		if err != nil {
			return err
		}
		if err := updates.VerifyMinisign(key.PublicKey, nil, proof); err != nil {
			return fmt.Errorf("release secret does not match the root statement: %w", err)
		}
		if deadline.After(key.ExpiresAt) {
			return errors.New("manifest expiry must not outlive the release key")
		}
		file, err := openUpdateToolInput(*installer)
		if err != nil {
			return err
		}
		hash := sha256.New()
		size, hashErr := io.Copy(hash, io.LimitReader(file, updates.MaxInstallerSize+1))
		closeErr := file.Close()
		if err := errors.Join(hashErr, closeErr); err != nil {
			return err
		}
		if size <= 0 || size > updates.MaxInstallerSize {
			return errors.New("installer exceeds its size limit")
		}
		manifest := updates.Manifest{Product: "net-switch", Architecture: *architecture, Version: *version, URL: updates.InstallerURL(*version, *architecture), SHA256: hex.EncodeToString(hash.Sum(nil)), Size: size, IssuedAt: now, ExpiresAt: deadline}
		raw, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return err
		}
		signature, err := updates.SignMinisign(string(secret), raw, "Net Switch "+*architecture+" update "+*version)
		if err != nil {
			return err
		}
		return writeSignedUpdateOutput(*output, raw, signature)
	}
	return errors.New("unknown update signing command")
}

func loadUpdateSigningSecret(path, environment string) ([]byte, error) {
	if (path == "") == (environment == "") {
		return nil, errors.New("signing requires exactly one of --key or --key-env")
	}
	if path != "" {
		return readUpdateToolFile(path, 16384)
	}
	// The environment variable's name, never its value, appears in argv and
	// workflow logs. Offline root issuance deliberately has no such option.
	value, exists := os.LookupEnv(environment)
	if !exists || len(value) == 0 || len(value) > 16384 {
		return nil, errors.New("release signing key environment variable is missing or invalid")
	}
	return []byte(value), nil
}

func requestControlUpdate(version string, statusOnly bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	rpc, err := ConnectDesktop(ctx, false)
	if err != nil {
		return err
	}
	defer rpc.Close()
	var session struct{ URL, Token string }
	if err := rpc.Call(ctx, map[string]any{"method": "session"}, &session); err != nil {
		return err
	}
	client, err := desktop.NewClient(session.URL, session.Token)
	if err != nil {
		return err
	}
	if statusOnly {
		state, err := client.FetchState(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(state["updateStatus"])
	}
	state, err := client.CheckForUpdate(ctx)
	if err != nil {
		return err
	}
	offer, _ := state["update"].(map[string]any)
	if offer["packageManager"] == true {
		return errors.New("update with your package manager")
	}
	offered, _ := offer["version"].(string)
	if offered == "" || (version != "" && version != offered) {
		return errors.New("the requested signed update is not available")
	}
	state, err = client.ApplyUpdateState(ctx, offered)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(state["updateStatus"])
}

func verifyUpdateCommand(rootPath, statementPath, manifestPath, current, architecture, installer string) error {
	if statementPath == "" || manifestPath == "" || !updates.CanonicalVersion(current) {
		return errors.New("verification requires --key-statement, --manifest, --current and --arch")
	}
	root := updates.RootPublicKey
	if rootPath != "" {
		bytes, err := readUpdateToolFile(rootPath, 16384)
		if err != nil {
			return err
		}
		root = string(bytes)
	}
	var bundle updates.Bundle
	for _, file := range []struct {
		path   string
		target *[]byte
	}{
		{statementPath, &bundle.Key}, {statementPath + ".minisig", &bundle.KeySignature},
		{manifestPath, &bundle.Manifest}, {manifestPath + ".minisig", &bundle.ManifestSignature},
	} {
		bytes, err := readUpdateToolFile(file.path, updates.MaxMetadataSize)
		if err != nil {
			return err
		}
		*file.target = bytes
	}
	manifest, err := updates.VerifyBundle(root, bundle, current, architecture, time.Now())
	if err != nil {
		return err
	}
	if installer != "" {
		file, err := openUpdateToolInput(installer)
		if err != nil {
			return err
		}
		err = manifest.VerifyInstaller(file)
		closeErr := file.Close()
		if err := errors.Join(err, closeErr); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(manifest)
}

func readUpdateToolFile(path string, maximum int64) ([]byte, error) {
	f, err := openUpdateToolInput(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximum {
		return nil, errors.New("signing input exceeds its size limit")
	}
	return raw, nil
}

func writeSignedUpdateOutput(path string, raw, signature []byte) error {
	if err := createUpdateToolFile(path, raw, false); err != nil {
		return err
	}
	if err := createUpdateToolFile(path+".minisig", signature, false); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}
