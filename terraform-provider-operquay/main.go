package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/operquay/terraform-provider-operquay/internal/client"
	"github.com/operquay/terraform-provider-operquay/internal/provider"
)

const version = "0.1.0"

func main() {
	var (
		describeSchema bool
		showVersion    bool
		planFile       string
		applyFile      string
		destroyFile    string
		endpoint       string
		caCert         string
		email          string
		password       string
		token          string
	)
	flag.BoolVar(&describeSchema, "describe-schema", false, "Print provider resource schema JSON")
	flag.BoolVar(&showVersion, "version", false, "Print provider version")
	flag.StringVar(&planFile, "plan", "", "Path to JSON manifest to plan")
	flag.StringVar(&applyFile, "apply", "", "Path to JSON manifest to apply")
	flag.StringVar(&destroyFile, "destroy", "", "Path to JSON manifest to destroy")
	flag.StringVar(&endpoint, "endpoint", os.Getenv("OPERQUAY_ENDPOINT"), "Operquay server URL")
	flag.StringVar(&caCert, "ca-cert", os.Getenv("OPERQUAY_CA_CERT"), "Path to trusted CA PEM")
	flag.StringVar(&email, "email", os.Getenv("OPERQUAY_EMAIL"), "Login email")
	flag.StringVar(&password, "password", os.Getenv("OPERQUAY_PASSWORD"), "Login password")
	flag.StringVar(&token, "token", os.Getenv("OPERQUAY_TOKEN"), "Bearer token")
	flag.Parse()

	if showVersion {
		fmt.Println("terraform-provider-operquay", version)
		return
	}
	if describeSchema {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"provider": "operquay",
			"version":  version,
			"schemas":  provider.Schemas(),
		})
		return
	}
	if planFile != "" {
		manifest := mustLoadManifest(planFile)
		plan, err := provider.Plan(manifest)
		if err != nil {
			fatalf("plan error: %v", err)
		}
		printJSON(plan)
		return
	}
	if applyFile != "" {
		manifest := mustLoadManifest(applyFile)
		cli := mustClient(endpoint, caCert, email, password, token)
		res, err := provider.Apply(context.Background(), cli, manifest)
		if err != nil {
			fatalf("apply error: %v", err)
		}
		printJSON(res)
		return
	}
	if destroyFile != "" {
		manifest := mustLoadManifest(destroyFile)
		cli := mustClient(endpoint, caCert, email, password, token)
		if err := provider.Destroy(context.Background(), cli, manifest); err != nil {
			fatalf("destroy error: %v", err)
		}
		fmt.Println(`{"destroyed":true}`)
		return
	}

	fmt.Fprintln(os.Stderr, "Usage: terraform-provider-operquay [--describe-schema | --plan <file> | --apply <file> | --destroy <file> | --version]")
	os.Exit(2)
}

func mustLoadManifest(path string) provider.Manifest {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatalf("read %s: %v", path, err)
	}
	var m provider.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		fatalf("parse %s: %v", path, err)
	}
	return m
}

func mustClient(endpoint, caCert, email, password, token string) *client.Client {
	cli, err := client.NewClient(client.Config{
		Endpoint:   endpoint,
		CACertPath: caCert,
		Email:      email,
		Password:   password,
		Token:      token,
	})
	if err != nil {
		fatalf("client init: %v", err)
	}
	return cli
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
